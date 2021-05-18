/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package agent.lldb.model.impl;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import SWIG.SBValue;
import agent.lldb.lldb.DebugClient;
import agent.lldb.model.iface2.LldbModelTargetStackFrameRegister;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetElementType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.dbg.util.ConversionUtils;
import ghidra.dbg.util.PathUtils;

@TargetObjectSchemaInfo(
	name = "RegisterValue",
	elements = {
		@TargetElementType(type = Void.class) },
	attributes = {
		@TargetAttributeType(type = Void.class) })
public class LldbModelTargetStackFrameRegisterImpl
		extends LldbModelTargetObjectImpl
		implements LldbModelTargetStackFrameRegister {

	protected static String indexRegister(SBValue register) {
		return register.GetName();
	}

	protected static String keyRegister(SBValue register) {
		return PathUtils.makeKey(indexRegister(register));
	}

	protected final SBValue register;
	private String value;

	protected final int bitLength;

	public LldbModelTargetStackFrameRegisterImpl(LldbModelTargetStackFrameRegisterBankImpl bank,
			SBValue register) {
		super(bank.getModel(), bank, keyRegister(register), "Register");
		this.getModel().addModelObject(DebugClient.getRegisterId(register), this);
		this.register = register;
		this.value = register.GetValue();
		this.getModel().addModelObject(DebugClient.getRegisterId(register), this);
		
		this.bitLength = (int) (register.GetByteSize() * 8);

		changeAttributes(List.of(), Map.of( //
			CONTAINER_ATTRIBUTE_NAME, bank, //
			LENGTH_ATTRIBUTE_NAME, getBitLength(), //
			DISPLAY_ATTRIBUTE_NAME, getName()+":"+value, //
			VALUE_ATTRIBUTE_NAME, value == null ? "" : value, //
			MODIFIED_ATTRIBUTE_NAME, false //
		), "Initialized");
	}

	@Override
	public int getBitLength() {
		return bitLength;
	}

	@Override
	public SBValue getRegister() {
		return register;
	}
	
	public byte [] getBytes() {
		BigInteger val = new BigInteger(value);
		byte[] bytes = ConversionUtils.bigIntegerToBytes((int) register.GetByteSize(), val);
		return bytes;
	}

}
