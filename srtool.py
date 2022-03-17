# !/usr/bin/python3

# Author: Germano Sobroza
# email: germanoavs@gmail.com; germano@ita.br
# Feel free to use it

from gc import garbage
from numpy import fromfile
import argparse


class Unpacker(object):
	def __init__(self):
		self.telemetry = None

	def unpackAX25(self, ax25pkt):
		frameIndex = 0
		dst = ""

		for i in range(0, 6):
			dst += chr((ax25pkt[frameIndex] & 0xFF) >> 1)
			frameIndex += 1

			# Get Destination SSID
		dstSSID = ((ax25pkt[frameIndex] & 0x0F) >> 1)
		frameIndex += 1

		# Get Command or Response Message Type
		if ((ax25pkt[6] >> 7) == 0x01):
			cmdMsg = True
		else:
			cmdMsg = False

			# Get Source Address
		src = ""
		for i in range(0, 6):
			src += chr((ax25pkt[frameIndex] & 0xFF) >> 1)
			frameIndex += 1

			# Get Source SSID
		srcSSID = ((ax25pkt[frameIndex] & 0x0F) >> 1)
		frameIndex += 1

		# Get Control Filed
		control = (ax25pkt[frameIndex] & 0xFF)
		frameIndex += 1

		# Get PID Field
		pid = (ax25pkt[frameIndex] & 0xFF)
		frameIndex += 1

		# Get Payload Length
		payloadLength = len(ax25pkt) - frameIndex

		# Get Payload
		payload = []
		for i in range(0, payloadLength):
			# payload.append((msg[frameIndex] & 0xFF))
			payload.append(hex(ax25pkt[frameIndex] & 0xFF))
			frameIndex += 1

		# Dict

		unpackedAX25 = {
			'SOURCE' : src,
			'SSSID' : srcSSID,
			'DESTINATION' : dst,
			'DSSID' : dstSSID,
			'PID' : pid,
			'CONTROL' : control,
			'PAYLOAD' : payload
		}

		return payload, unpackedAX25

	def unpackSP(self, sp):
		# this function receives a space packet in 'bytes' format and returns dict with all fields  

		# get pkt len -> bytes 4 e 5
		pktLen = int.from_bytes(sp[4:6], "big", signed=False) + 1

		# get paket data field from space packet
		pkt_data_field = sp[-pktLen:]


		# get data from space packet
		dataBeac = pkt_data_field[8:-2]

		#get primary header
		pkt_primary_header = sp[:-pktLen]

		# set first bit (Seq HDR Flag) to '0' and keep only APID
		APID = int.from_bytes(pkt_primary_header[0:2], 'big')& (0xFFFF >>5) 		# set the 5 first bits to '0'

		# get Sec HDR Flag
		secHDRflag = ((pkt_primary_header[0] & 0x0F) & (0xFF << 3))>>3	

		# get Version No
		versN = (((pkt_primary_header[0])) & (0xFF << 5)) >> 5

		#get pkt type
		pktType = (pkt_primary_header[0] & (0x01 << 4)) >> 4

		pkt_seq_control = pkt_primary_header[2:4]

		#get Sequence Flag
		seqFlag = (int.from_bytes(pkt_seq_control, 'big') & (0xFFFF << 14)) >> 14

		# get Sequence Count
		seqCount = (int.from_bytes(pkt_seq_control,'big') & (0xFFFF >> 2))

		#get secondary header as two uint32
		secondary_header = [
			int.from_bytes(pkt_data_field[0:4],'big'),
			int.from_bytes(pkt_data_field[4:8],'big')
		]

		# get TC id, valid only if it's  pkt type = 1
		TCid = dataBeac[0:2]

		# Checksum 
		cks = pkt_data_field[-2:]

		# dict with all fields 
		spacePkt = {
			'Version No' : versN,
			'Pkt Type'	: pktType,
			'Sec HDR Flag' : secHDRflag,
			'APID' : APID,
			'Seq Flags' : seqFlag,
			'Seq Count' : seqCount,
			'Pkt Data Len': pktLen,
			'Secondary Header' : secondary_header,
			'TC ID' : TCid,
			'DATA' : dataBeac, 
			'CKS' : cks
		}
	
		# returns a tuple with data and aPID
		return spacePkt

	def unpack_AX25_SP(self,ax25pkt):

		sp_, garbage = self.unpackAX25(ax25pkt)			# unpack ax25
		sp_ = bytes([int(x,0) for x in sp_])	# transform list of hex in bytes
		spDict = self.unpackSP(sp_)		# get only data field
		return spDict



if __name__ == '__main__':
	# arguments and commands definition
	parser = argparse.ArgumentParser('Unpack Space Packets.')
	groupInput = parser.add_mutually_exclusive_group()
	groupInput.add_argument('-b', action='store_true', help = 'Activate binary data input, otherwise it a txt file with HEX')
	groupInput.add_argument('-s', action='store_true', help = 'Activate string input with hex values, otherwise its a txt file with HEX')
	groupWorker = parser.add_mutually_exclusive_group()
	groupWorker.add_argument('-a', action='store_true', help = 'AX25 unpacking mode, otherwise ax25+SP unpacking.')
	groupWorker.add_argument('-sp', action='store_true', help = 'Space Packet unpacking mode, otherwise ax25+SP unpacking.')
	parser.add_argument('file_path', type=str, help='file path of binary data or hex txt')

	# take arguments
	args = parser.parse_args()


	# INPUT TYPES
	# if binary file mode is active, opens file 
	if args.b:
		ax25_or_SP_pkt = fromfile(args.file_path, dtype='uint8')

	elif args.s:	# if input is a string with hex values
		ax25_or_SP_pkt = bytearray.fromhex(args.file_path)
	else:
		# Open command file
		with open(args.file_path, 'r') as f:
			msg_str = f.readline()
			ax25_or_SP_pkt = bytearray.fromhex(msg_str) 
			f.close()

	# WHAT TO DO 


	# TODO: new commands for only ax25 unpacking, only sp unpacking and both
	myUnpacker = Unpacker()

	if args.a:
		payload, dict = (myUnpacker.unpackAX25(ax25_or_SP_pkt))
	elif args.sp:
		dict = myUnpacker.unpackSP(ax25_or_SP_pkt)

	else:
		dict = myUnpacker.unpack_AX25_SP(ax25_or_SP_pkt)


	print(dict)