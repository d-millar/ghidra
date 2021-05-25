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
import java.util.concurrent.atomic.AtomicReference;

import SWIG.SBProcess;
import SWIG.SBTarget;
import agent.lldb.manager.LldbCause;
import agent.lldb.model.iface2.LldbModelTargetSessionAttributes;
import agent.lldb.model.iface2.LldbModelTargetSessionAttributesMachine;
import ghidra.async.AsyncUtils;
import ghidra.async.TypeSpec;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetElementType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;

@TargetObjectSchemaInfo(
	name = "SessionAttributesMachine",
	elements = {
		@TargetElementType(type = Void.class)
	},
	attributes = {
		@TargetAttributeType(name = "Arch", type = String.class),
		@TargetAttributeType(name = "Debugger", type = String.class),
		@TargetAttributeType(name = "OS", type = String.class),
		@TargetAttributeType(name = "Mode", type = String.class),
		@TargetAttributeType(name = "Version", type = String.class),
		@TargetAttributeType(type = Void.class)
	})
public class LldbModelTargetSessionAttributesMachineImpl extends LldbModelTargetObjectImpl
		implements LldbModelTargetSessionAttributesMachine {

	static String ARCH_ATTRIBUTE_NAME = "Arch";
	static String DEBUGGER_ATTRIBUTE_NAME = "Debugger";
	static String OS_ATTRIBUTE_NAME = "OS";

	public LldbModelTargetSessionAttributesMachineImpl(LldbModelTargetSessionAttributes attributes) {
		super(attributes.getModel(), attributes, "Machine", "SessionMachineAttributes");

		changeAttributes(List.of(), List.of(), Map.of( //
			ARCH_ATTRIBUTE_NAME, "x86_64", //
			DEBUGGER_ATTRIBUTE_NAME, "lldb", //
			OS_ATTRIBUTE_NAME, "OSX" //
		), "Initialized");

		getManager().addEventsListener(this);
	}

	@Override
	public void sessionAdded(SBTarget session, LldbCause cause) {
		refreshInternal();
	}

	@Override
	public void processAdded(SBProcess process, LldbCause cause) {
		refreshInternal();
	}

	public void refreshInternal() {
		/*
		DebugControl control = getManager().getControl();
		int processorType = control.getActualProcessorType();
		if (processorType < 0) {
			return;
		}
		Machine machine = Machine.getByNumber(processorType);
		int debuggeeType = control.getDebuggeeType();
		DebugClass debugClass = DebugClientInternal.DebugClass.values()[debuggeeType];
		changeAttributes(List.of(), List.of(), Map.of( //
			ARCH_ATTRIBUTE_NAME, machine.description, //
			"Mode", debugClass.toString() //
		), "Refreshed");
		*/

		AtomicReference<String> capture = new AtomicReference<>();
		AsyncUtils.sequence(TypeSpec.VOID).then(seq -> {
			getManager().consoleCapture("version").handle(seq::next);
		}, capture).then(seq -> {
			changeAttributes(List.of(), List.of(), Map.of( //
				"Version", capture.get()), "Refreshed");
		}).finish();
	}

}
