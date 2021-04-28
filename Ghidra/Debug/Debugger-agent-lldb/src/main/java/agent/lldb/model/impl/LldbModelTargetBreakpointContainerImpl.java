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

import agent.lldb.manager.LldbCause;
import agent.lldb.manager.breakpoint.LldbBreakpointInfo;
import agent.lldb.manager.impl.LldbManagerImpl;
import agent.lldb.model.iface2.LldbModelTargetBreakpointContainer;
import agent.lldb.model.iface2.LldbModelTargetBreakpointSpec;
import agent.lldb.model.iface2.LldbModelTargetDebugContainer;
import agent.lldb.model.iface2.LldbModelTargetThread;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointKind;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetElementType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;

@TargetObjectSchemaInfo(name = "BreakpointContainer", elements = { //
	@TargetElementType(type = LldbModelTargetBreakpointSpecImpl.class) //
}, attributes = { //
	@TargetAttributeType(type = Void.class) //
}, canonicalContainer = true)
public class LldbModelTargetBreakpointContainerImpl extends LldbModelTargetObjectImpl
		implements LldbModelTargetBreakpointContainer {

	protected static final TargetBreakpointKindSet SUPPORTED_KINDS =
		TargetBreakpointKindSet.of(TargetBreakpointKind.values());

	public LldbModelTargetBreakpointContainerImpl(LldbModelTargetDebugContainer debug) {
		super(debug.getModel(), debug, "Breakpoints", "BreakpointContainer");

		getManager().addEventsListener(this);

		changeAttributes(List.of(), List.of(), Map.of(  //
			// TODO: Seems terrible to duplicate this static attribute on each instance
			SUPPORTED_BREAK_KINDS_ATTRIBUTE_NAME, SUPPORTED_KINDS //
		), "Initialized");
	}

	@Override
	public void breakpointCreated(LldbBreakpointInfo info, LldbCause cause) {
		changeElements(List.of(), List.of(getTargetBreakpointSpec(info)), Map.of(), "Created");
	}

	@Override
	public void breakpointModified(LldbBreakpointInfo newInfo, LldbBreakpointInfo oldInfo,
			LldbCause cause) {
		getTargetBreakpointSpec(oldInfo).updateInfo(oldInfo, newInfo, "Modified");
	}

	@Override
	public void breakpointDeleted(LldbBreakpointInfo info, LldbCause cause) {
		LldbModelImpl impl = (LldbModelImpl) model;
		impl.deleteModelObject(info.getDebugBreakpoint());
		changeElements(List.of( //
			LldbModelTargetBreakpointSpecImpl.indexBreakpoint(info) //
		), List.of(), Map.of(), "Deleted");
	}

	@Override
	public void breakpointHit(LldbBreakpointInfo info, LldbCause cause) {
		LldbModelTargetThread targetThread =
			getParentProcess().getThreads().getTargetThread(getManager().getEventThread());
		LldbModelTargetBreakpointSpec spec = getTargetBreakpointSpec(info);
		listeners.fire.breakpointHit(getProxy(), targetThread, null, spec, spec);
		spec.breakpointHit();
	}

	public LldbModelTargetBreakpointSpec getTargetBreakpointSpec(LldbBreakpointInfo info) {
		LldbModelImpl impl = (LldbModelImpl) model;
		TargetObject modelObject = impl.getModelObject(info.getDebugBreakpoint());
		if (modelObject != null) {
			return (LldbModelTargetBreakpointSpec) modelObject;
		}
		return new LldbModelTargetBreakpointSpecImpl(this, info);
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		LldbManagerImpl manager = getManager();
		return manager.listBreakpoints().thenAccept(byNumber -> {
			List<TargetObject> specs;
			synchronized (this) {
				specs = byNumber.values()
						.stream()
						.map(this::getTargetBreakpointSpec)
						.collect(Collectors.toList());
			}
			setElements(specs, Map.of(), "Refreshed");
		});
	}
}
