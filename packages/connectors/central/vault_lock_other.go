//go:build !darwin && !linux

package central

import "os"

func vaultRegularFile(os.FileInfo) bool      { return false }
func openVaultFile(string) (*os.File, error) { return nil, ErrVaultRead }
func lockVault(string) (*os.File, error)     { return nil, ErrVaultLock }
func unlockVault(file *os.File)              { _ = file.Close() }
