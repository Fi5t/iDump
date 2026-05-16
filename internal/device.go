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
			return nil, fmt.Errorf("waiting for USB device: %w", ctx.Err())
		case <-changed:
		}
	}
}

func GetApplications(device frida.DeviceInt) ([]*frida.Application, error) {
	apps, err := device.EnumerateApplications("", frida.ScopeMinimal)
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate applications: %w", err)
	}
	return apps, nil
}

func ListApplications(device frida.DeviceInt) error {
	apps, err := GetApplications(device)
	if err != nil {
		return err
	}

	sort.SliceStable(apps, func(i, j int) bool {
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
	return strconv.Itoa(a.PID())
}

// Does NOT resume the process; call device.Resume(pid) after injecting any bypass script.
func SpawnAndAttach(ctx context.Context, device frida.DeviceInt, nameOrBundleID string) (session *frida.Session, pid int, displayName, bundleID string, err error) {
	ui.Step("Attaching to " + nameOrBundleID)

	apps, err := GetApplications(device)
	if err != nil {
		return nil, 0, "", "", err
	}

	for _, a := range apps {
		if nameOrBundleID == a.Identifier() || nameOrBundleID == a.Name() {
			pid = a.PID()
			displayName = a.Name()
			bundleID = a.Identifier()
			break
		}
	}

	if bundleID == "" {
		return nil, 0, "", "", fmt.Errorf("app not found: %s", nameOrBundleID)
	}

	if pid != 0 {
		ui.Step("Restarting for a clean session")
		if kerr := device.Kill(pid); kerr != nil {
			ui.Warn(fmt.Sprintf("kill pid %d: %v", pid, kerr))
		}
		timer := time.NewTimer(time.Second)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return nil, 0, "", "", fmt.Errorf("waiting for restart: %w", ctx.Err())
		case <-timer.C:
		}
	}

	spawnedPID, err := device.Spawn(bundleID, nil)
	if err != nil {
		return nil, 0, "", "", fmt.Errorf("failed to spawn %s: %w", bundleID, err)
	}
	session, err = device.Attach(spawnedPID, nil)
	if err != nil {
		if kerr := device.Kill(spawnedPID); kerr != nil {
			ui.Warn(fmt.Sprintf("kill pid %d: %v", spawnedPID, kerr))
		}
		return nil, 0, "", "", fmt.Errorf("failed to attach to pid %d: %w", spawnedPID, err)
	}

	return session, spawnedPID, displayName, bundleID, nil
}

func OpenTargetApp(ctx context.Context, device frida.DeviceInt, nameOrBundleID string) (session *frida.Session, displayName, bundleID string, err error) {
	var pid int
	session, pid, displayName, bundleID, err = SpawnAndAttach(ctx, device, nameOrBundleID)
	if err != nil {
		return nil, "", "", err
	}
	if err = device.Resume(pid); err != nil {
		return nil, "", "", fmt.Errorf("failed to resume pid %d: %w", pid, err)
	}
	return session, displayName, bundleID, nil
}

func OpenApp(ctx context.Context, device frida.DeviceInt, target, bypassScript string) (*frida.Session, string, error) {
	if bypassScript != "" {
		session, pid, displayName, _, err := SpawnAndAttach(ctx, device, target)
		if err != nil {
			return nil, "", err
		}
		if err = InjectBypass(session, bypassScript); err != nil {
			if derr := session.Detach(); derr != nil {
				ui.Warn(fmt.Sprintf("detach after inject failure: %v", derr))
			}
			if kerr := device.Kill(pid); kerr != nil {
				ui.Warn(fmt.Sprintf("kill pid %d after inject failure: %v", pid, kerr))
			}
			return nil, "", fmt.Errorf("inject bypass: %w", err)
		}
		if err = device.Resume(pid); err != nil {
			if derr := session.Detach(); derr != nil {
				ui.Warn(fmt.Sprintf("detach after resume failure: %v", derr))
			}
			if kerr := device.Kill(pid); kerr != nil {
				ui.Warn(fmt.Sprintf("kill pid %d after resume failure: %v", pid, kerr))
			}
			return nil, "", fmt.Errorf("resume: %w", err)
		}
		return session, displayName, nil
	}
	session, displayName, _, err := OpenTargetApp(ctx, device, target)
	if err != nil {
		return nil, "", err
	}
	return session, displayName, nil
}
