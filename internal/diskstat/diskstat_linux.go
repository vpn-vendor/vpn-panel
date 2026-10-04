package diskstat

import "syscall"

func Usage(path string) (Space, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return Space{}, err
	}
	bs := uint64(st.Bsize) //nolint:gosec
	return Space{
		Total:       st.Blocks * bs,
		Free:        st.Bfree * bs,
		AvailUnpriv: st.Bavail * bs,
	}, nil
}
