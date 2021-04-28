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

import agent.lldb.model.iface2.LldbModelTargetDebugContainer;
import agent.lldb.model.iface2.LldbModelTargetProcess;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;

@TargetObjectSchemaInfo(
	name = "DebugContainer",
	attributes = {
		@TargetAttributeType(
			name = "Breakpoints",
			type = LldbModelTargetBreakpointContainerImpl.class,
			required = true,
			fixed = true),
		@TargetAttributeType(type = Void.class)
	},
	canonicalContainer = true)
public class LldbModelTargetDebugContainerImpl extends LldbModelTargetObjectImpl
		implements LldbModelTargetDebugContainer {

	protected final LldbModelTargetBreakpointContainerImpl breakpoints;
	private LldbModelTargetProcess process;

	public LldbModelTargetDebugContainerImpl(LldbModelTargetProcess process) {
		super(process.getModel(), process, "Debug", "DebugContainer");
		this.process = process;

		this.breakpoints = new LldbModelTargetBreakpointContainerImpl(this);

		changeAttributes(List.of(), List.of(  //
			breakpoints //
		), Map.of(), "Initialized");
	}

}
