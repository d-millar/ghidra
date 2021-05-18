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

import SWIG.SBBreakpointLocation;
import SWIG.SBTarget;
import agent.lldb.lldb.DebugClient;
import agent.lldb.model.iface2.LldbModelTargetBreakpointContainer;
import agent.lldb.model.iface2.LldbModelTargetBreakpointLocation;
import agent.lldb.model.iface2.LldbModelTargetBreakpointLocationContainer;
import agent.lldb.model.iface2.LldbModelTargetBreakpointSpec;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetElementType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;

@TargetObjectSchemaInfo(name = "BreakpointContainer", elements = { //
	@TargetElementType(type = LldbModelTargetBreakpointSpecImpl.class) //
}, attributes = { //
	@TargetAttributeType(type = Void.class) //
}, canonicalContainer = true)
public class LldbModelTargetBreakpointLocationContainerImpl extends LldbModelTargetObjectImpl
		implements LldbModelTargetBreakpointLocationContainer {

	protected final LldbModelTargetBreakpointSpecImpl targetBreakpoint;
	private final SBTarget session;

	public LldbModelTargetBreakpointLocationContainerImpl(LldbModelTargetBreakpointSpec targetBreakpoint, SBTarget session) {
		super(targetBreakpoint.getModel(), targetBreakpoint, "BreakpointLocations", "BreakpointLocationContainer");
		this.targetBreakpoint = (LldbModelTargetBreakpointSpecImpl) targetBreakpoint;
		this.session = session;

		getManager().addEventsListener(this);
	}

	public LldbModelTargetBreakpointLocation getTargetBreakpointLocation(SBBreakpointLocation loc) {
		LldbModelImpl impl = (LldbModelImpl) model;
		TargetObject modelObject = impl.getModelObject(DebugClient.getBreakpointLocationId(loc));
		if (modelObject != null) {
			return (LldbModelTargetBreakpointLocation) modelObject;
		}
		return new LldbModelTargetBreakpointLocationImpl(this, loc);
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		return getManager().listBreakpointLocations(targetBreakpoint.bpt).thenAccept(byNumber -> {
			List<TargetObject> specs;
			synchronized (this) {
				specs = byNumber.values()
						.stream()
						.map(this::getTargetBreakpointLocation)
						.collect(Collectors.toList());
			}
			setElements(specs, Map.of(), "Refreshed");
		});
	}

	public SBTarget getSession() {
		return session;
	}
}
