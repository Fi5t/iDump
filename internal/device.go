package internal

import (
	"context"
	"errors"
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

type SpawnResult struct {
	Session     *frida.Session
	PID         int
	DisplayName string
	BundleID    string
	Suspended   bool
}

// Does NOT resume the process; call device.Resume(pid) after injecting any bypass script.
// If the app is already running, attaches directly without re-spawning; Suspended is false in that case.
func SpawnAndAttach(ctx context.Context, device frida.DeviceInt, nameOrBundleID string) (SpawnResult, error) {
	ui.Step("Attaching to " + nameOrBundleID)

	apps, err := GetApplications(device)
	if err != nil {
		return SpawnResult{}, err
	}

	var res SpawnResult
	for _, a := range apps {
		if nameOrBundleID == a.Identifier() || nameOrBundleID == a.Name() {
			res.PID = a.PID()
			res.DisplayName = a.Name()
			res.BundleID = a.Identifier()
			break
		}
	}

	if res.BundleID == "" {
		return SpawnResult{}, fmt.Errorf("app not found: %s", nameOrBundleID)
	}

	if res.PID != 0 {
		ui.Step("App is already running, attaching directly")
		attachCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		res.Session, err = device.AttachWithContext(attachCtx, res.PID, nil)
		if err != nil {
			if attachCtx.Err() != nil {
				return SpawnResult{}, errors.New("attach timed out — app may be in the background; bring it to the foreground and retry")
			}
			return SpawnResult{}, fmt.Errorf("failed to attach to pid %d: %w", res.PID, err)
		}
		return res, nil
	}

	spawnedPID, err := device.Spawn(res.BundleID, nil)
	if err != nil {
		return SpawnResult{}, fmt.Errorf("failed to spawn %s: %w", res.BundleID, err)
	}
	res.Session, err = device.Attach(spawnedPID, nil)
	if err != nil {
		if kerr := device.Kill(spawnedPID); kerr != nil {
			ui.Warn(fmt.Sprintf("kill pid %d: %v", spawnedPID, kerr))
		}
		return SpawnResult{}, fmt.Errorf("failed to attach to pid %d: %w", spawnedPID, err)
	}

	res.PID = spawnedPID
	res.Suspended = true
	return res, nil
}

func OpenTargetApp(ctx context.Context, device frida.DeviceInt, nameOrBundleID string) (session *frida.Session, displayName, bundleID string, err error) {
	res, err := SpawnAndAttach(ctx, device, nameOrBundleID)
	if err != nil {
		return nil, "", "", err
	}
	if res.Suspended {
		if err = device.Resume(res.PID); err != nil {
			return nil, "", "", fmt.Errorf("failed to resume pid %d: %w", res.PID, err)
		}
	}
	return res.Session, res.DisplayName, res.BundleID, nil
}

func OpenApp(ctx context.Context, device frida.DeviceInt, target, bypassScript string) (*frida.Session, string, error) {
	if bypassScript != "" {
		res, err := SpawnAndAttach(ctx, device, target)
		if err != nil {
			return nil, "", err
		}
		if !res.Suspended {
			ui.Warn("app was already running — bypass injected live, not at spawn; detection hooks may have already fired")
		}
		if err = InjectBypass(res.Session, bypassScript); err != nil {
			if derr := res.Session.Detach(); derr != nil {
				ui.Warn(fmt.Sprintf("detach after inject failure: %v", derr))
			}
			if res.Suspended {
				if kerr := device.Kill(res.PID); kerr != nil {
					ui.Warn(fmt.Sprintf("kill pid %d after inject failure: %v", res.PID, kerr))
				}
			}
			return nil, "", fmt.Errorf("inject bypass: %w", err)
		}
		if res.Suspended {
			if err = device.Resume(res.PID); err != nil {
				if derr := res.Session.Detach(); derr != nil {
					ui.Warn(fmt.Sprintf("detach after resume failure: %v", derr))
				}
				if kerr := device.Kill(res.PID); kerr != nil {
					ui.Warn(fmt.Sprintf("kill pid %d after resume failure: %v", res.PID, kerr))
				}
				return nil, "", fmt.Errorf("resume: %w", err)
			}
		}
		return res.Session, res.DisplayName, nil
	}
	session, displayName, _, err := OpenTargetApp(ctx, device, target)
	if err != nil {
		return nil, "", err
	}
	return session, displayName, nil
}
