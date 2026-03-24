//go:build !windows
// +build !windows

package apps

import (
	"os"
	"syscall"
)

// daemonize performs a very small, pragmatic daemonization:
// it re-execs the current process with Setsid enabled so the child is detached.
// On success the parent exits. The child receives an environment variable
// _GONC_DAEMONIZED=1 so we don't recurse.
func daemonize(ncconfig *AppNetcatConfig) error {
	if !ncconfig.daemon {
		return nil
	}
	// If already daemonized (child), do nothing.
	if os.Getenv("_GONC_DAEMONIZED") == "1" {
		return nil
	}

	// Prepare attributes for the child process.
	files := []*os.File{os.Stdin, os.Stdout, os.Stderr}
	attr := &os.ProcAttr{
		Dir:   ".",
		Env:   append(os.Environ(), "_GONC_DAEMONIZED=1"),
		Files: files,
		Sys: &syscall.SysProcAttr{
			Setsid: true,
		},
	}

	exe, err := os.Executable()
	if err != nil {
		return err
	}

	// Re-exec the same binary with same args.
	proc, err := os.StartProcess(exe, os.Args, attr)
	if err != nil {
		ncconfig.Logger.Printf("Failed to start daemonized process: %v\n", err)
		return err
	}

	ncconfig.Logger.Printf("Daemon process started with pid %d\n", proc.Pid)
	// Parent should exit immediately.
	os.Exit(0)
	return nil
}
