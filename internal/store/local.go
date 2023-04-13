package store

type Local struct {
	Folder string
}

func NewLocal(folder string) Store {
	return Local{
		Folder: folder,
	}
}

func (l Local) Connect() error {
	panic("not implemented") // TODO: Implement
}

func (l Local) Put(key []byte, value []byte) error {
	panic("not implemented") // TODO: Implement
}

func (l Local) Get(key []byte) ([]byte, error) {
	panic("not implemented") // TODO: Implement
}

func (l Local) Delete(key []byte) error {
	panic("not implemented") // TODO: Implement
}

func (l Local) Close() error {
	panic("not implemented") // TODO: Implement
}
