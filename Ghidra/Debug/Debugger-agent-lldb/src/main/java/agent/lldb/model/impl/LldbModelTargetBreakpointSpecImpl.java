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

import SWIG.*;
import agent.lldb.lldb.DebugClient;
import agent.lldb.model.iface2.*;
import ghidra.dbg.target.TargetBreakpointLocation;
import ghidra.dbg.target.TargetBreakpointSpec;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.dbg.util.PathUtils;
import ghidra.util.datastruct.ListenerSet;

@TargetObjectSchemaInfo(name = "BreakpointSpec", attributes = { //
	@TargetAttributeType( //
		name = "Locations", type = LldbModelTargetBreakpointLocationContainerImpl.class), //
	@TargetAttributeType( //
		name = TargetBreakpointSpec.CONTAINER_ATTRIBUTE_NAME, //
		type = LldbModelTargetBreakpointContainerImpl.class), //
	@TargetAttributeType( //
		name = TargetBreakpointLocation.SPEC_ATTRIBUTE_NAME, //
		type = LldbModelTargetBreakpointSpecImpl.class), //
	@TargetAttributeType(name = LldbModelTargetBreakpointSpecImpl.BPT_TYPE_ATTRIBUTE_NAME, type = String.class), //
	@TargetAttributeType(name = LldbModelTargetBreakpointSpecImpl.BPT_DISP_ATTRIBUTE_NAME, type = Boolean.class), //
	@TargetAttributeType(name = LldbModelTargetBreakpointSpecImpl.BPT_VALID_ATTRIBUTE_NAME, type = Boolean.class), //
	@TargetAttributeType(name = LldbModelTargetBreakpointSpecImpl.BPT_TIMES_ATTRIBUTE_NAME, type = Long.class), //
	@TargetAttributeType(type = Void.class) //
}, canonicalContainer = true)
public class LldbModelTargetBreakpointSpecImpl extends LldbModelTargetObjectImpl
		implements LldbModelTargetBreakpointSpec {

	protected static String keyBreakpoint(Object bpt) {
		return PathUtils.makeKey(DebugClient.getId(bpt));
	}

	private LldbModelTargetBreakpointContainer breakpoints;
	private LldbModelTargetBreakpointLocationContainer locations;
	protected boolean enabled;

	public void changeAttributeSet(String reason) {
		Object info = getBreakpointInfo();
		if (info instanceof SBBreakpoint) {
			SBBreakpoint bpt = (SBBreakpoint) info;
			this.changeAttributes(List.of(), List.of(
				locations //
			), Map.of( //
				DISPLAY_ATTRIBUTE_NAME, getDescription(0), //
				SPEC_ATTRIBUTE_NAME, this, //
				KINDS_ATTRIBUTE_NAME, getKinds() //
			), reason);
			this.changeAttributes(List.of(), List.of(), Map.of( //
				BPT_TYPE_ATTRIBUTE_NAME, bpt.IsHardware() ? "Hardware" : "Software", //
				BPT_DISP_ATTRIBUTE_NAME, bpt.IsEnabled(), //
				BPT_VALID_ATTRIBUTE_NAME, bpt.IsValid(), //
				BPT_TIMES_ATTRIBUTE_NAME, bpt.GetHitCount() //
			), reason);
		}
	}

	private final ListenerSet<TargetBreakpointAction> actions =
		new ListenerSet<>(TargetBreakpointAction.class) {
			// Use strong references on actions
			protected Map<TargetBreakpointAction, TargetBreakpointAction> createMap() {
				return Collections.synchronizedMap(new LinkedHashMap<>());
			}
		};

	public LldbModelTargetBreakpointSpecImpl(LldbModelTargetBreakpointContainer breakpoints,
			Object bpt) {
		super(breakpoints.getModel(), breakpoints, keyBreakpoint(bpt), bpt, "BreakpointSpec");
		this.breakpoints = breakpoints;
	
		this.locations = new LldbModelTargetBreakpointLocationContainerImpl(this, breakpoints.getSession());

		changeAttributeSet("Refreshed");
	}

	@Override
	public Object getBreakpointInfo() {
		return getModelObject();
	}

	public String getDescription(int level) {
		SBStream stream = new SBStream();
		Object modelObject = getModelObject();
		if (modelObject instanceof SBBreakpoint) {
			SBBreakpoint bpt = (SBBreakpoint) modelObject;
			bpt.GetDescription(stream);
		}
		if (modelObject instanceof SBWatchpoint) {
			SBWatchpoint wpt = (SBWatchpoint) modelObject;		
			DescriptionLevel detail = DescriptionLevel.swigToEnum(level);
			wpt.GetDescription(stream, detail);
		}
		return stream.GetData();
	}

	@Override
	public void setBreakpointId(String id) {
		throw new AssertionError();
	}

	/**
	 * Update the enabled field
	 * 
	 * This does not actually toggle the breakpoint. It just updates the field
	 * and calls the proper listeners. To actually toggle the breakpoint, use
	 * {@link #toggle(boolean)} instead, which if effective, should eventually
	 * cause this method to be called.
	 * 
	 * @param enabled true if enabled, false if disabled
	 * @param reason a description of the cause (not really used, yet)
	 */
	@Override
	public void setEnabled(boolean enabled, String reason) {
		setBreakpointEnabled(enabled);
		changeAttributes(List.of(), List.of(), Map.of(ENABLED_ATTRIBUTE_NAME, enabled //
		), reason);
	}

	@Override
	public boolean isBreakpointEnabled() {
		return enabled;
	}

	@Override
	public void setBreakpointEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	@Override
	public ListenerSet<TargetBreakpointAction> getActions() {
		return actions;
	}
	
}
