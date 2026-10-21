//go:build darwin || linux

package central

import (
	"os"
	"syscall"
)

func vaultRegularFile(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.Mode().IsRegular() && info.Mode().Perm() == 0600 && stat.Nlink == 1 && stat.Uid == uint32(os.Getuid())
}

func openVaultFile(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrVaultRead
	}
	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	if err != nil || !vaultRegularFile(info) {
		_ = file.Close()
		return nil, ErrVaultRead
	}
	return file, nil
}

func lockVault(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, ErrVaultLock
	}
	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	if err != nil || !vaultRegularFile(info) {
		_ = file.Close()
		return nil, ErrVaultLock
	}
	if syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		_ = file.Close()
		return nil, ErrVaultInUse
	}
	return file, nil
}

func unlockVault(file *os.File) {
	_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	_ = file.Close()
}
