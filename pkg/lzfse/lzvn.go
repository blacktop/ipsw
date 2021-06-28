package lzfse

type lzvnOpCode byte

const (
	nop lzvnOpCode = iota
	end_of_stream
	undefined

	small_literal
	large_literal

	small_match
	large_match

	small_distance
	large_distance
	medium_distance
	previous_distance
)

var opcode_table = [256]lzvnOpCode{
	small_distance, small_distance, small_distance, small_distance, small_distance, small_distance, end_of_stream, large_distance,
	small_distance, small_distance, small_distance, small_distance, small_distance, small_distance, nop, large_distance,
	small_distance, small_distance, small_distance, small_distance, small_distance, small_distance, nop, large_distance,
	small_distance, small_distance, small_distance, small_distance, small_distance, small_distance, undefined, large_distance,
	small_distance, small_distance, small_distance, small_distance, small_distance, small_distance, undefined, large_distance,
	small_distance, small_distance, small_distance, small_distance, small_distance, small_distance, undefined, large_distance,
	small_distance, small_distance, small_distance, small_distance, small_distance, small_distance, undefined, large_distance,
	small_distance, small_distance, small_distance, small_distance, small_distance, small_distance, undefined, large_distance,
	small_distance, small_distance, small_distance, small_distance, small_distance, small_distance, previous_distance, large_distance,
	small_distance, small_distance, small_distance, small_distance, small_distance, small_distance, previous_distance, large_distance,
	small_distance, small_distance, small_distance, small_distance, small_distance, small_distance, previous_distance, large_distance,
	small_distance, small_distance, small_distance, small_distance, small_distance, small_distance, previous_distance, large_distance,
	small_distance, small_distance, small_distance, small_distance, small_distance, small_distance, previous_distance, large_distance,
	small_distance, small_distance, small_distance, small_distance, small_distance, small_distance, previous_distance, large_distance,
	undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined,
	undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined,
	small_distance, small_distance, small_distance, small_distance, small_distance, small_distance, previous_distance, large_distance,
	small_distance, small_distance, small_distance, small_distance, small_distance, small_distance, previous_distance, large_distance,
	small_distance, small_distance, small_distance, small_distance, small_distance, small_distance, previous_distance, large_distance,
	small_distance, small_distance, small_distance, small_distance, small_distance, small_distance, previous_distance, large_distance,
	medium_distance, medium_distance, medium_distance, medium_distance, medium_distance, medium_distance, medium_distance, medium_distance,
	medium_distance, medium_distance, medium_distance, medium_distance, medium_distance, medium_distance, medium_distance, medium_distance,
	medium_distance, medium_distance, medium_distance, medium_distance, medium_distance, medium_distance, medium_distance, medium_distance,
	medium_distance, medium_distance, medium_distance, medium_distance, medium_distance, medium_distance, medium_distance, medium_distance,
	small_distance, small_distance, small_distance, small_distance, small_distance, small_distance, previous_distance, large_distance,
	small_distance, small_distance, small_distance, small_distance, small_distance, small_distance, previous_distance, large_distance,
	undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined,
	undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined,
	large_literal, small_literal, small_literal, small_literal, small_literal, small_literal, small_literal, small_literal,
	small_literal, small_literal, small_literal, small_literal, small_literal, small_literal, small_literal, small_literal,
	large_match, small_match, small_match, small_match, small_match, small_match, small_match, small_match,
	small_match, small_match, small_match, small_match, small_match, small_match, small_match, small_match,
}
