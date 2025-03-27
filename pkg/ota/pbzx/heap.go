package pbzx

type _Heap []_Chunk

func (h _Heap) Len() int {
	return len(h)
}

func (h _Heap) Less(i, j int) bool {
	return h[i].idx < h[j].idx
}

func (h _Heap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
}

func (h *_Heap) Push(x any) {
	*h = append(*h, x.(_Chunk))
}

func (h *_Heap) Pop() (x any) {
	last := len(*h) - 1
	x = (*h)[last]
	*h = (*h)[:last]
	return
}
