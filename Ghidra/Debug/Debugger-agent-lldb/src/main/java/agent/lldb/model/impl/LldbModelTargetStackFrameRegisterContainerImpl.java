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

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import SWIG.SBValue;
import SWIG.StateType;
import agent.lldb.lldb.DebugClient;
import agent.lldb.manager.LldbReason;
import agent.lldb.model.iface2.LldbModelTargetRegisterBank;
import agent.lldb.model.iface2.LldbModelTargetStackFrameRegisterContainer;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetObjectSchema.ResyncMode;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;

@TargetObjectSchemaInfo(
	name = "RegisterValueContainer",
	elementResync = ResyncMode.ONCE,
	attributes = {
		@TargetAttributeType(type = Void.class) },
	canonicalContainer = true)
public class LldbModelTargetStackFrameRegisterContainerImpl
		extends LldbModelTargetObjectImpl
		implements LldbModelTargetStackFrameRegisterContainer {
	public static final String NAME = "Registers";

	protected final LldbModelTargetStackFrameImpl frame;

	public LldbModelTargetStackFrameRegisterContainerImpl(LldbModelTargetStackFrameImpl frame) {
		super(frame.getModel(), frame, NAME, "StackFrameRegisterContainer");
		this.frame = frame;
		requestElements(false);
	}

	/**
	 * Does both descriptions and then populates values
	 */
	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		return getManager().listStackFrameRegisterBanks(frame.frame).thenAccept(banks -> {
			List<TargetObject> targetBanks;
			synchronized (this) {
				targetBanks = banks.values().stream().map(this::getTargetRegisterBank).collect(Collectors.toList());
			}
			setElements(targetBanks, Map.of(), "Refreshed");
		}); 
	}


	@Override
	public LldbModelTargetRegisterBank getTargetRegisterBank(SBValue val) {
		LldbModelImpl impl = (LldbModelImpl) model;
		TargetObject modelObject = impl.getModelObject(DebugClient.getBankId(frame.frame, val));
		if (modelObject != null) {
			return (LldbModelTargetRegisterBank) modelObject;
		}
		return new LldbModelTargetStackFrameRegisterBankImpl(this, val);
	}

	public void threadStateChangedSpecific(StateType state, LldbReason reason) {
		if (state.equals(StateType.eStateStopped)) {
			for (TargetObject element : getCallbackElements().values()) {
				if (element instanceof LldbModelTargetRegisterBank) {
					LldbModelTargetRegisterBank bank = (LldbModelTargetRegisterBank) element;
					bank.threadStateChangedSpecific(state, reason);
				}
			} 
		}
	}

}
