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

import SWIG.*;
import agent.lldb.model.iface2.*;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.*;

@TargetObjectSchemaInfo(name = "BreakpointLocationContainer", elements = { //
	@TargetElementType(type = LldbModelTargetBreakpointLocationImpl.class) //
}, attributes = { //
	@TargetAttributeType(type = Void.class) //
}, canonicalContainer = true)
public class LldbModelTargetBreakpointLocationContainerImpl extends LldbModelTargetObjectImpl
		implements LldbModelTargetBreakpointLocationContainer {

	protected final LldbModelTargetBreakpointSpecImpl targetBreakpoint;

	public LldbModelTargetBreakpointLocationContainerImpl(LldbModelTargetBreakpointSpec targetBreakpoint, SBTarget session) {
		super(targetBreakpoint.getModel(), targetBreakpoint, "Locations", "BreakpointLocationContainer");
		this.targetBreakpoint = (LldbModelTargetBreakpointSpecImpl) targetBreakpoint;

		getManager().addEventsListener(this);
		requestElements(false);
	}

	public LldbModelTargetBreakpointLocation getTargetBreakpointLocation(SBBreakpointLocation loc) {
		TargetObject targetObject = getMapObject(loc);
		if (targetObject != null) {
			LldbModelTargetBreakpointLocation location = (LldbModelTargetBreakpointLocation) targetObject;
			location.setModelObject(loc);
			return location;
		}
		return new LldbModelTargetBreakpointLocationImpl(this, loc);
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		return getManager().listBreakpointLocations((SBBreakpoint)(targetBreakpoint).getBreakpointInfo()).thenAccept(byNumber -> {
			List<TargetObject> locs;
			synchronized (this) {
				locs = byNumber.values()
						.stream()
						.map(this::getTargetBreakpointLocation)
						.collect(Collectors.toList());
			}
			setElements(locs, Map.of(), "Refreshed");
		});
	}

	public SBTarget getSession() {
		return (SBTarget) getModelObject();
	}
}
