// +build windows

package file

func execCopy(src, dst string) error {
	return CopyFile(src, dst)
}
