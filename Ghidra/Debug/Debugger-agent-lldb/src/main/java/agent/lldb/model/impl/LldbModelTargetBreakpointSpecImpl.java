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

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import SWIG.SBBreakpoint;
import SWIG.SBTarget;
import agent.lldb.lldb.DebugClient;
import agent.lldb.manager.breakpoint.LldbBreakpointInfo;
import agent.lldb.model.iface2.LldbModelTargetBreakpointContainer;
import agent.lldb.model.iface2.LldbModelTargetBreakpointSpec;
import ghidra.dbg.target.TargetBreakpointLocation;
import ghidra.dbg.target.TargetBreakpointSpec;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.dbg.util.PathUtils;
import ghidra.util.datastruct.ListenerSet;

@TargetObjectSchemaInfo(name = "BreakpointSpec", attributes = { //
	@TargetAttributeType( //
			name = TargetBreakpointSpec.CONTAINER_ATTRIBUTE_NAME, //
			type = LldbModelTargetBreakpointContainerImpl.class), //
	@TargetAttributeType( //
			name = TargetBreakpointLocation.SPEC_ATTRIBUTE_NAME, //
			type = LldbModelTargetBreakpointSpecImpl.class), //
	@TargetAttributeType(name = LldbModelTargetBreakpointSpecImpl.BPT_TYPE_ATTRIBUTE_NAME, type = String.class), //
	@TargetAttributeType(name = LldbModelTargetBreakpointSpecImpl.BPT_DISP_ATTRIBUTE_NAME, type = String.class), //
	@TargetAttributeType(name = LldbModelTargetBreakpointSpecImpl.BPT_PENDING_ATTRIBUTE_NAME, type = String.class), //
	@TargetAttributeType(name = LldbModelTargetBreakpointSpecImpl.BPT_TIMES_ATTRIBUTE_NAME, type = Integer.class), //
	@TargetAttributeType(type = Void.class) //
}, canonicalContainer = true)
public class LldbModelTargetBreakpointSpecImpl extends LldbModelTargetObjectImpl
		implements LldbModelTargetBreakpointSpec {

	protected static String keyBreakpoint(SBBreakpoint bpt) {
		return PathUtils.makeKey(Integer.toHexString(bpt.GetID()));
	}

	private LldbModelTargetBreakpointContainer breakpoints;
	protected SBBreakpoint bpt;
	protected boolean enabled;

	public void changeAttributeSet(String reason) {
		/*
		this.changeAttributes(List.of(), List.of(), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, "[" + bpt.GetID() + "] " + bpt.getExpression(), //
			ADDRESS_ATTRIBUTE_NAME, doGetAddress(), //
			LENGTH_ATTRIBUTE_NAME, bpt.getSize(), //
			SPEC_ATTRIBUTE_NAME, this, //
			EXPRESSION_ATTRIBUTE_NAME, bpt.getExpression(), //
			KINDS_ATTRIBUTE_NAME, getKinds() //
		), reason);
		this.changeAttributes(List.of(), List.of(), Map.of( //
			BPT_TYPE_ATTRIBUTE_NAME, bpt.getType().name(), //
			BPT_DISP_ATTRIBUTE_NAME, bpt.getDisp().name(), //
			BPT_PENDING_ATTRIBUTE_NAME, bpt.getPending(), //
			BPT_TIMES_ATTRIBUTE_NAME, bpt.getTimes() //
		), reason);
		*/
	}

	private final ListenerSet<TargetBreakpointAction> actions =
		new ListenerSet<>(TargetBreakpointAction.class) {
			// Use strong references on actions
			protected Map<TargetBreakpointAction, TargetBreakpointAction> createMap() {
				return Collections.synchronizedMap(new LinkedHashMap<>());
			}
		};

	public LldbModelTargetBreakpointSpecImpl(LldbModelTargetBreakpointContainer breakpoints,
			SBBreakpoint bpt) {
		super(breakpoints.getModel(), breakpoints, keyBreakpoint(bpt), "BreakpointSpec");
		this.breakpoints = breakpoints;
		this.bpt = bpt;
		this.getModel().addModelObject(DebugClient.getBreakpointId(bpt), this);
		//this.setBreakpointInfo(info);

		updateInfo(bpt, "Created");
	}

	@Override
	public void updateInfo(SBBreakpoint bpt, String reason) {
		synchronized (this) {
			setBreakpointInfo(bpt);
		}
		changeAttributeSet("Refreshed");
		setEnabled(bpt.IsEnabled(), reason);
	}

	@Override
	public SBBreakpoint getBreakpointInfo() {
		return bpt;
	}

	@Override
	public void setBreakpointId(String id) {
		throw new AssertionError();
	}

	@Override
	public void setBreakpointInfo(SBBreakpoint bpt) {
		this.bpt = bpt;
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

	protected CompletableFuture<SBBreakpoint> getInfo() {
		SBTarget session = breakpoints.getSession();
		return getManager().listBreakpoints(session)
				.thenApply(__ -> getManager().getKnownBreakpoints(session).get(getNumber()));
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		return getInfo().thenAccept(i -> {
			synchronized (this) {
				setBreakpointInfo(i);
			}
			changeAttributeSet("Initialized");
		});
	}

}
