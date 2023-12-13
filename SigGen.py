# Name: SigGen.py
# Version: 1.0.3
# Author: RenardDev (zeze839@gmail.com)

# IDA imports
import ida_idaapi
import ida_ua
import ida_bytes
import ida_pro
import ida_auto
import ida_ida
import ida_search
import idc

def IsNotValidAddress(address):
	if (address == 0) | (address == ida_idaapi.BADADDR):
		return True
	return False

def DecodeInstruction(address):
	if IsNotValidAddress(address):
		return None
	insn = ida_ua.insn_t()
	if ida_ua.decode_insn(insn, address):
		return insn
	return None

def BytesToString(bytes):
	return ' '.join(map(lambda x: f'{x:02X}', bytes))

def IsOperandIdpSpec(op):
	return (op.type == ida_ua.o_idpspec0) | (op.type == ida_ua.o_idpspec1) | (op.type == ida_ua.o_idpspec2) | (op.type == ida_ua.o_idpspec3) | (op.type == ida_ua.o_idpspec4) | (op.type == ida_ua.o_idpspec5)

def GetInstructionSignature(address, show_mask):
	insn = DecodeInstruction(address)
	if insn:
		insn_bytes = ida_bytes.get_bytes(address, insn.size)
		if insn.ops[0].type == ida_ua.o_void:
			return (insn, BytesToString(insn_bytes))
		else:
			insn_signature = BytesToString(insn_bytes[:insn.ops[0].offb])
			op_pairs = [(i, insn.ops[i], insn.ops[i + 1]) for i in range(len(insn.ops) - 1)]
			for i, op, next_op in op_pairs:
				if (op.type == ida_ua.o_void) | ((i > 0) & (op.offb == 0)):
					break
				if next_op.offb != 0:
					op_size = next_op.offb - op.offb
				else:
					op_size = insn.size - op.offb
				if IsOperandIdpSpec(op):
					insn_signature += BytesToString(insn_bytes[op.offb:op.offb + op_size])
				elif op.type == ida_ua.o_reg:
					insn_signature += BytesToString(insn_bytes[op.offb:op.offb + op_size])
				elif op.type == ida_ua.o_phrase:
					insn_signature += BytesToString(insn_bytes[op.offb:op.offb + op_size])
				else:
					if show_mask:
						insn_signature += ' ?' * op_size
			return (insn, insn_signature)
	return (None, None)

def GetInstructionSignatureBytes(address):
	insn = DecodeInstruction(address)
	if insn:
		insn_bytes = ida_bytes.get_bytes(address, insn.size)
		insn_signature_bytes = bytearray()
		if insn.ops[0].type == ida_ua.o_void:
			insn_signature_bytes.extend(insn_bytes)
			return (insn, insn_signature_bytes)
		else:
			insn_signature_bytes.extend(insn_bytes[:insn.ops[0].offb])
			op_pairs = [(i, insn.ops[i], insn.ops[i + 1]) for i in range(len(insn.ops) - 1)]
			for i, op, next_op in op_pairs:
				if (op.type == ida_ua.o_void) | ((i > 0) & (op.offb == 0)):
					break
				if next_op.offb != 0:
					op_size = next_op.offb - op.offb
				else:
					op_size = insn.size - op.offb
				if IsOperandIdpSpec(op):
					insn_signature_bytes.extend(insn_bytes[op.offb:op.offb + op_size])
				elif op.type == ida_ua.o_reg:
					insn_signature_bytes.extend(insn_bytes[op.offb:op.offb + op_size])
				elif op.type == ida_ua.o_phrase:
					insn_signature_bytes.extend(insn_bytes[op.offb:op.offb + op_size])
			return (insn, insn_signature_bytes)
	return (None, None)

def MakeSignature(address, insn_count):
	signature = ''
	i = 0
	offset = 0
	while i < insn_count:
		insn, insn_signature = GetInstructionSignature(address + offset, i + 1 < insn_count)
		if insn_signature:
			signature += insn_signature
			if i + 1 < insn_count:
				signature += ' '
			offset += insn.size
			i += 1
		else:
			return None
	return signature

def Adler32(bytes):
	MOD_ADLER = 65521
	a = 1
	b = 0

	for byte in bytes:
		a = (a + byte) % MOD_ADLER
		b = (b + a) % MOD_ADLER

	return (b << 16) | a

def MakeFunctionHash(start_address, end_address):
	signature_bytes = bytearray()
	offset = 0
	while start_address + offset < end_address:
		if offset >= 0xFFFF:
			break
		insn, insn_signature_bytes = GetInstructionSignatureBytes(start_address + offset)
		if insn_signature_bytes:
			signature_bytes.extend(insn_signature_bytes)
			offset += insn.size
		else:
			signature_bytes.extend(ida_bytes.get_bytes(start_address + offset, 1))
			offset += 1
	return ((Adler32(signature_bytes) & ~0xFFFF) | offset, signature_bytes)

class SigGen(ida_idaapi.plugin_t):
	flags = ida_idaapi.PLUGIN_MOD
	wanted_name = 'SigGen'
	wanted_hotkey = 'Ctrl+Shift+M'
	comment = 'SigGen - Signature Generator.\n'
	help = ''

	def init(self):
		if ida_pro.IDA_SDK_VERSION < 770:
			idc.msg('[SigGen] Error: Optimal IDA version for SigGen is 7.7.\n')
			return ida_idaapi.PLUGIN_SKIP
		return ida_idaapi.PLUGIN_KEEP

	def term(self):
		pass

	def run(self, arg):
		if ida_auto.auto_is_ok() != True:
			idc.msg('[SigGen] Error: The analysis is not finished!\n')
			return

		min_address = ida_ida.inf_get_min_ea()
		max_address = ida_ida.inf_get_max_ea()

		current_address = idc.here()
		if ida_bytes.is_code(ida_bytes.get_flags(current_address)) != True:
			idc.msg('[SigGen] Error: The cursor is not on the code!\n')
			return

		count = 1
		while count < 64:
			signature = MakeSignature(current_address, count)
			if signature:
				if IsNotValidAddress(ida_search.find_binary(min_address, current_address - 1, signature, 0, ida_search.SEARCH_DOWN)) & IsNotValidAddress(ida_search.find_binary(current_address + 1, max_address, signature, 0, ida_search.SEARCH_DOWN)):
					func_start = idc.get_func_attr(current_address, idc.FUNCATTR_START)
					func_end = idc.get_func_attr(current_address, idc.FUNCATTR_END)
					if current_address == func_start:
						func_hash, signature_bytes = MakeFunctionHash(func_start, func_end)
						if func_hash:
							idc.msg(f'Signature (Hash: 0x{func_hash:08X}): {signature}\n')
						else:
							break
					else:
						idc.msg(f'Signature: {signature}\n')
					return
				else:
					count += 1
					continue
			else:
				break

		idc.msg('Failed to generate signature.\n')

_SigGen = None
bPluginMode = False
def PLUGIN_ENTRY():
	global _SigGen
	global bPluginMode
	if _SigGen == None:
		_SigGen = SigGen()
	bPluginMode = True
	return _SigGen

if __name__ == '__main__':
	if bPluginMode != True:
		if ida_pro.IDA_SDK_VERSION < 770:
			idc.msg('[SigGen] Error: Optimal IDA version for SigGen is 7.7.\n')
		else:
			SigGen().run(0)
