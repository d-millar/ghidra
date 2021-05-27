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
import agent.lldb.manager.LldbReason;
import agent.lldb.model.iface2.*;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.dbg.target.schema.TargetObjectSchema.ResyncMode;

@TargetObjectSchemaInfo(
	name = "RegisterContainer",
	attributeResync = ResyncMode.ALWAYS,
	attributes = {
		@TargetAttributeType(
			name = "General Purpose Registers",
			type = LldbModelTargetStackFrameRegisterBank.class,
			required = true),
		@TargetAttributeType(
			name = "Exception State Registers",
			type = LldbModelTargetStackFrameRegisterNullBank.class, 
			required = true),
		@TargetAttributeType(
			name = "Floating Point Registers",
			type = LldbModelTargetStackFrameRegisterNullBank.class, 
			required = true),
		@TargetAttributeType(type = Void.class) 
	},
	canonicalContainer = true)
public class LldbModelTargetStackFrameRegisterContainerImpl
		extends LldbModelTargetObjectImpl
		implements LldbModelTargetStackFrameRegisterContainer {
	public static final String NAME = "Registers";

	protected final LldbModelTargetStackFrameImpl frame;

	public LldbModelTargetStackFrameRegisterContainerImpl(LldbModelTargetStackFrameImpl frame) {
		super(frame.getModel(), frame, NAME, "StackFrameRegisterContainer");
		this.frame = frame;
		requestAttributes(true);
	}

	/**
	 * Does both descriptions and then populates values
	 */
	@Override
	public CompletableFuture<Void> requestAttributes(boolean refresh) {
		return getManager().listStackFrameRegisterBanks(frame.getFrame()).thenAccept(banks -> {
			List<TargetObject> targetBanks;
			synchronized (this) {
				targetBanks = banks.values().stream().map(this::getTargetRegisterBank).collect(Collectors.toList());
			}
			changeAttributes(List.of(), targetBanks, Map.of(), "Refreshed");
		}); 
	}


	@Override
	public LldbModelTargetObject getTargetRegisterBank(SBValue val) {
		TargetObject targetObject = getMapObject(val);
		if (targetObject != null) {
			LldbModelTargetObject targetBank = (LldbModelTargetObject) targetObject;
			targetBank.setModelObject(val);
			return targetBank;
		}
		if (val.GetName().contains("General")) {
			return new LldbModelTargetStackFrameRegisterBankImpl(this, val);
		} else {
			return new LldbModelTargetStackFrameRegisterNullBankImpl(this, val);
		}
	}

	public void threadStateChangedSpecific(StateType state, LldbReason reason) {
		if (state.equals(StateType.eStateStopped)) {
			requestAttributes(false).thenAccept(__ -> {
				for (TargetObject element : getCachedElements().values()) {
					if (element instanceof LldbModelTargetRegisterBank) {
						LldbModelTargetRegisterBank bank = (LldbModelTargetRegisterBank) element;
						bank.threadStateChangedSpecific(state, reason);
					}
					if (element instanceof LldbModelTargetStackFrameRegisterNullBank) {
						LldbModelTargetStackFrameRegisterNullBankImpl bank = (LldbModelTargetStackFrameRegisterNullBankImpl) element;
						bank.threadStateChangedSpecific(state, reason);
					}
				} 
			});
		}
	}

}
