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

// Pop removes the last heap element and clears its backing-array slot so
// the decoded chunk buffer can be reclaimed.
func (h *_Heap) Pop() (x any) {
	last := len(*h) - 1
	x = (*h)[last]
	(*h)[last] = _Chunk{}
	*h = (*h)[:last]
	return
}
