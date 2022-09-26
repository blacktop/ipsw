package pbzx

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
)

func read(ctx context.Context, src io.Reader, inflateCh, writeCh chan<- _Chunk) error {
	defer close(inflateCh)

	magic := make([]byte, 4)
	if _, err := io.ReadFull(src, magic); err != nil {
		return fmt.Errorf("read error: %w", err)
	}
	if string(magic) != "pbzx" {
		return fmt.Errorf("pbzx magic mismatch")
	}

	var blockSize uint64
	if err := binary.Read(src, binary.BigEndian, &blockSize); err != nil {
		return fmt.Errorf("read error: %w", err)
	}

	var idx int
	for {
		var inflateSize, deflateSize uint64
		if err := binary.Read(src, binary.BigEndian, &inflateSize); err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("read error: %w", err)
		}
		if err := binary.Read(src, binary.BigEndian, &deflateSize); err != nil {
			return fmt.Errorf("read error: %w", err)
		}
		data := make([]byte, deflateSize)
		if _, err := io.ReadFull(src, data); err != nil {
			return fmt.Errorf("read error: %w", err)
		}

		if uint64(int(inflateSize)) != inflateSize {
			return fmt.Errorf("bad chunk header")
		}

		chunk := _Chunk{
			idx:  idx,
			meta: int(inflateSize),
			data: data,
		}
		switch {
		case deflateSize < inflateSize:
			select {
			case <-ctx.Done():
				return ctx.Err()
			case inflateCh <- chunk:
			}
		case deflateSize == inflateSize:
			select {
			case <-ctx.Done():
				return ctx.Err()
			case writeCh <- chunk:
			}
		case deflateSize > inflateSize:
			return fmt.Errorf("bad chunk header")
		}

		idx += 1
	}
}
