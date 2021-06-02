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

import java.util.*;
import java.util.stream.Collectors;

import SWIG.SBBreakpoint;
import SWIG.SBStream;
import agent.lldb.model.iface2.LldbModelTargetBreakpointContainer;
import agent.lldb.model.iface2.LldbModelTargetBreakpointLocation;
import ghidra.dbg.target.TargetBreakpointLocation;
import ghidra.dbg.target.TargetBreakpointSpecContainer.TargetBreakpointKindSet;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointAction;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.util.datastruct.ListenerSet;

@TargetObjectSchemaInfo(
	name = "BreakpointSpec",
	attributes = {
		@TargetAttributeType(name = "Type", type = String.class),
		@TargetAttributeType(name = "Valid", type = Boolean.class),
		@TargetAttributeType(name = "Enabled", type = Boolean.class),
		@TargetAttributeType(name = "Count", type = Long.class),
		@TargetAttributeType(type = Void.class)
	},
	canonicalContainer = true)
public class LldbModelTargetBreakpointSpecImpl extends LldbModelTargetAbstractXpointSpec {

	protected final ListenerSet<TargetBreakpointAction> actions =
		new ListenerSet<>(TargetBreakpointAction.class) {
			// Use strong references on actions
			protected Map<TargetBreakpointAction, TargetBreakpointAction> createMap() {
				return Collections.synchronizedMap(new LinkedHashMap<>());
			};
		};

	public LldbModelTargetBreakpointSpecImpl(LldbModelTargetBreakpointContainer breakpoints,
			Object info) {
		super(breakpoints, info, "BreakpointSpec");
	}

	public String getDescription(int level) {
		SBStream stream = new SBStream();
		SBBreakpoint bpt = (SBBreakpoint) getModelObject();
		bpt.GetDescription(stream);
		return stream.GetData();
	}

	protected TargetBreakpointKindSet computeKinds(Object from) {
		return TargetBreakpointKindSet.of(TargetBreakpointKind.SW_EXECUTE);
	}

	public void updateInfo(Object info, String reason) {
		setModelObject(info);
		updateAttributesFromInfo(reason);
		getManager().listBreakpointLocations((SBBreakpoint) info).thenAccept(byNumber -> {
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

	public void updateAttributesFromInfo(String reason) {
		SBBreakpoint bpt = (SBBreakpoint) getModelObject();
		this.changeAttributes(List.of(), List.of(), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, display = getDescription(0), //
			KINDS_ATTRIBUTE_NAME, kinds = computeKinds(bpt), //
			ENABLED_ATTRIBUTE_NAME, enabled = bpt.IsEnabled(), //
			EXPRESSION_ATTRIBUTE_NAME, "" //
		), reason);
		this.changeAttributes(List.of(), List.of(), Map.of( //
			BPT_TYPE_ATTRIBUTE_NAME, bpt.IsHardware() ? "Hardware" : "Software", //
			BPT_DISP_ATTRIBUTE_NAME, bpt.IsEnabled(), //
			BPT_VALID_ATTRIBUTE_NAME, bpt.IsValid(), //
			BPT_TIMES_ATTRIBUTE_NAME, bpt.GetHitCount() //
		), reason);
		Map<String, TargetObject> cachedElements = getCachedElements();
		if (!cachedElements.isEmpty()) {
			Object[] elements = cachedElements.values().toArray();
			LldbModelTargetBreakpointLocationImpl loc =
				(LldbModelTargetBreakpointLocationImpl) elements[0];
			this.changeAttributes(List.of(), List.of(), Map.of( //
				TargetBreakpointLocation.ADDRESS_ATTRIBUTE_NAME, loc.address //
			), reason);
		}
	}

	public ListenerSet<TargetBreakpointAction> getActions() {
		return actions;
	}

	public LldbModelTargetBreakpointLocation findLocation(Object obj) {
		for (LldbModelTargetBreakpointLocation bp : breaksBySub.values()) {
			//if (!bp.loc.getInferiorIds().contains(frame.inferior.inferior.getId())) {
			//	continue;
			//}
			return bp;
		}
		return null;
	}

}
