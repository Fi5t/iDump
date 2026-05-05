package internal

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/frida/frida-go/frida"

	"github.com/Fi5t/idump/internal/ui"
)

func GetUSBDevice(ctx context.Context) (frida.DeviceInt, error) {
	mgr := frida.NewDeviceManager()

	changed := make(chan struct{}, 1)
	mgr.On("changed", func() {
		select {
		case changed <- struct{}{}:
		default:
		}
	})

	for {
		devices, err := mgr.EnumerateDevices()
		if err == nil {
			for _, d := range devices {
				if d.DeviceType() == frida.DeviceTypeUsb {
					return d, nil
				}
			}
		}
		ui.Step("Waiting for USB device...")
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-changed:
		}
	}
}

func getApplications(device frida.DeviceInt) ([]*frida.Application, error) {
	apps, err := device.EnumerateApplications("", frida.ScopeMinimal)
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate applications: %w", err)
	}
	return apps, nil
}

func ListApplications(device frida.DeviceInt) error {
	apps, err := getApplications(device)
	if err != nil {
		return err
	}

	sort.Slice(apps, func(i, j int) bool {
		iRunning := apps[i].PID() != 0
		jRunning := apps[j].PID() != 0
		if iRunning != jRunning {
			return iRunning
		}
		return apps[i].Name() < apps[j].Name()
	})

	pidW, nameW, idW := 3, 4, 10
	for _, a := range apps {
		pid := appPIDStr(a)
		if len(pid) > pidW {
			pidW = len(pid)
		}
		if len(a.Name()) > nameW {
			nameW = len(a.Name())
		}
		if len(a.Identifier()) > idW {
			idW = len(a.Identifier())
		}
	}

	hdr := fmt.Sprintf("%*s  %-*s  %-*s", pidW, "PID", nameW, "Name", idW, "Identifier")
	sep := fmt.Sprintf("%s  %s  %s", strings.Repeat("-", pidW), strings.Repeat("-", nameW), strings.Repeat("-", idW))
	fmt.Println(hdr)
	fmt.Println(sep)
	for _, a := range apps {
		fmt.Printf("%*s  %-*s  %-*s\n", pidW, appPIDStr(a), nameW, a.Name(), idW, a.Identifier())
	}
	return nil
}

func appPIDStr(a *frida.Application) string {
	if a.PID() == 0 {
		return "-"
	}
	return strconv.Itoa(int(a.PID()))
}

// OpenTargetApp finds the app by name or bundle ID, kills any running instance,
// spawns it fresh, attaches a Frida session, and returns the session along with
// the display name and bundle ID.
func OpenTargetApp(ctx context.Context, device frida.DeviceInt, nameOrBundleID string) (*frida.Session, string, string, error) {
	ui.Step("Attaching to " + nameOrBundleID)

	apps, err := getApplications(device)
	if err != nil {
		return nil, "", "", err
	}

	var pid int
	var displayName, bundleID string
	for _, a := range apps {
		if nameOrBundleID == a.Identifier() || nameOrBundleID == a.Name() {
			pid = a.PID()
			displayName = a.Name()
			bundleID = a.Identifier()
			break
		}
	}

	if bundleID == "" {
		return nil, "", "", fmt.Errorf("app not found: %s", nameOrBundleID)
	}

	if pid != 0 {
		ui.Step("Restarting for a clean session")
		_ = device.Kill(pid)
		timer := time.NewTimer(time.Second)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return nil, "", "", ctx.Err()
		case <-timer.C:
		}
	}

	spawnedPID, err := device.Spawn(bundleID, nil)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to spawn %s: %w", bundleID, err)
	}
	session, err := device.Attach(spawnedPID, nil)
	if err != nil {
		_ = device.Kill(spawnedPID)
		return nil, "", "", fmt.Errorf("failed to attach to pid %d: %w", spawnedPID, err)
	}
	if err := device.Resume(spawnedPID); err != nil {
		return nil, "", "", fmt.Errorf("failed to resume pid %d: %w", spawnedPID, err)
	}

	return session, displayName, bundleID, nil
}
