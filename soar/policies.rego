package access_policies

violation[packet.data] {
	packet := input.packet
    packet.data == 0
}