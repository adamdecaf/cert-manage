// +build windows

package file

func execCopy(src, dst string) error {
	// TODO(adam): This will probably require specific windows calls
	return CopyFile(src, dst)
}
