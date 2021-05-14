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
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import SWIG.SBValue;
import SWIG.StateType;
import agent.lldb.manager.LldbReason;
import agent.lldb.manager.LldbRegister;
import agent.lldb.model.iface2.LldbModelTargetRegister;
import agent.lldb.model.iface2.LldbModelTargetRegisterBank;
import agent.lldb.model.iface2.LldbModelTargetStackFrameRegisterBank;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetObjectSchema.ResyncMode;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.dbg.util.PathUtils;
import ghidra.util.datastruct.WeakValueHashMap;

@TargetObjectSchemaInfo(
	name = "RegisterValueContainer",
	elementResync = ResyncMode.ONCE,
	attributes = {
		@TargetAttributeType(type = Void.class) },
	canonicalContainer = true)
public class LldbModelTargetStackFrameRegisterBankImpl
		extends LldbModelTargetObjectImpl
		implements LldbModelTargetStackFrameRegisterBank {
	public static final String NAME = "Registers";

	protected static String keyValue(SBValue value) {
		return PathUtils.makeKey(value.GetName());
	}

	protected final LldbModelTargetStackFrameRegisterContainerImpl container;
	protected final SBValue value;

	private Map<String, byte[]> regValues = new HashMap<>();

	protected final Map<String, LldbModelTargetRegister> registersByName = new HashMap<>();

	protected final Map<Integer, LldbModelTargetStackFrameRegisterImpl> registersByNumber =
		new WeakValueHashMap<>();
	protected final Set<LldbRegister> allRegisters = new LinkedHashSet<>();

	public LldbModelTargetStackFrameRegisterBankImpl(LldbModelTargetStackFrameRegisterContainerImpl container, SBValue val) {
		super(container.getModel(), container, keyValue(val), "StackFrameRegisterBank");
		this.container = container;
		this.value = val;

		requestElements(false);
		changeAttributes(List.of(), List.of(),
		Map.of(
			DISPLAY_ATTRIBUTE_NAME, value.GetName(), 
			DESCRIPTIONS_ATTRIBUTE_NAME, this
		), "Initialized");
	}

	/**
	 * Does both descriptions and then populates values
	 */
	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		return getManager().listStackFrameRegisters(value).thenAccept(regs -> {
			if (regs.size() != registersByName.size()) {
				LldbModelImpl impl = (LldbModelImpl) model;
				for (SBValue reg : regs.values()) {
					impl.deleteModelObject(reg);
				}
				registersByName.clear();
		
			}
			List<TargetObject> registers;
			synchronized (this) {
				registers = regs.values().stream().map(this::getTargetRegister).collect(Collectors.toList());
			}
			setElements(registers, Map.of(), "Refreshed");
			if (!getCachedElements().isEmpty()) {
				readRegistersNamed(getCachedElements().keySet());
			}
		}); 
	}


	@Override
	public LldbModelTargetRegister getTargetRegister(SBValue register) {
		LldbModelImpl impl = (LldbModelImpl) model;
		TargetObject modelObject = impl.getModelObject(register);
		if (modelObject != null) {
			return (LldbModelTargetRegister) modelObject;
		}
		return new LldbModelTargetStackFrameRegisterImpl(this, register);
	}

	public void threadStateChangedSpecific(StateType state, LldbReason reason) {
		if (state.equals(StateType.eStateStopped)) {
			readRegistersNamed(getCachedElements().keySet());
		}
	}

	@Override
	public CompletableFuture<? extends Map<String, byte[]>> readRegistersNamed(
			Collection<String> names) {
		return null; /*model.gateFuture(ensureRegisterDescriptions().thenCompose(regs -> {
			Set<GdbRegister> toRead = new LinkedHashSet<>();
			for (String regname : names) {
				LldbModelTargetStackFrameRegisterImpl reg = regs.get(regname);
				if (reg == null) {
					throw new DebuggerRegisterAccessException("No such register: " + regname);
				}
				toRead.add(reg.register);
			}
			return updateRegisterValues(toRead);
		}));
		*/
	}
	
	@Override
	public CompletableFuture<Void> writeRegistersNamed(Map<String, byte[]> values) {
		Map<LldbRegister, BigInteger> toWrite = new LinkedHashMap<>();
		return null; /*model.gateFuture(ensureRegisterDescriptions().thenCompose(regs -> {
			for (Map.Entry<String, byte[]> ent : values.entrySet()) {
				String regname = ent.getKey();
				LldbModelTargetStackFrameRegisterImpl reg = regs.get(regname);
				if (reg == null) {
					throw new DebuggerRegisterAccessException("No such register: " + regname);
				}
				BigInteger val = new BigInteger(1, ent.getValue());
				toWrite.put(reg.register, val);
			}
			return frame.frame.writeRegisters(toWrite);
		}).thenCompose(__ -> {
			return updateRegisterValues(toWrite.keySet());
		})).thenApply(__ -> null);
		*/
	}
	
	@Override
	public Map<String, byte[]> getCachedRegisters() {
		return regValues;
	}

}
