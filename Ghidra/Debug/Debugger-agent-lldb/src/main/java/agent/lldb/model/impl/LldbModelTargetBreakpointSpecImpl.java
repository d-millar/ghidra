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
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import SWIG.*;
import agent.lldb.lldb.DebugClient;
import agent.lldb.model.iface2.*;
import ghidra.async.AsyncUtils;
import ghidra.dbg.target.TargetBreakpointSpecContainer.TargetBreakpointKindSet;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.dbg.util.PathUtils;
import ghidra.util.datastruct.ListenerSet;
import ghidra.util.datastruct.WeakValueHashMap;

@TargetObjectSchemaInfo(
	name = "BreakpointSpec",
	attributes = {
		@TargetAttributeType(type = Void.class) },
	canonicalContainer = true)
public class LldbModelTargetBreakpointSpecImpl extends LldbModelTargetObjectImpl
	implements LldbModelTargetBreakpointSpec {

	protected static String keyBreakpoint(Object bpt) {
		return PathUtils.makeKey(DebugClient.getId(bpt));
	}

	private LldbModelTargetBreakpointContainer breakpoints;

	protected long number;
	protected boolean enabled;
	protected String expression;
	protected String display;
	protected TargetBreakpointKindSet kinds;

	protected final Map<SBBreakpoint, LldbModelTargetBreakpointLocation> breaksBySub =
		new WeakValueHashMap<>();
	protected final ListenerSet<TargetBreakpointAction> actions =
		new ListenerSet<>(TargetBreakpointAction.class) {
			// Use strong references on actions
			protected Map<TargetBreakpointAction, TargetBreakpointAction> createMap() {
				return Collections.synchronizedMap(new LinkedHashMap<>());
			};
		};

	public LldbModelTargetBreakpointSpecImpl(LldbModelTargetBreakpointContainer breakpoints,
			Object info) {
		super(breakpoints.getModel(), breakpoints, keyBreakpoint(info), info, "BreakpointSpec");
		getModel().addModelObject(info, this);
		this.breakpoints = breakpoints;

		changeAttributes(List.of(), Map.of(CONTAINER_ATTRIBUTE_NAME, breakpoints), "Initialized");
	}

	protected CompletableFuture<Void> init() {
		Object info = getModelObject();
		updateInfo(info, "Created");
		return AsyncUtils.NIL;
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
	public CompletableFuture<Void> delete() {
		return getModel().gateFuture(getManager().deleteBreakpoints(number));
	}

	@Override
	public boolean isEnabled() {
		return enabled;
	}

	@Override
	public String getExpression() {
		return expression;
	}

	protected TargetBreakpointKindSet computeKinds(Object from) {
		return TargetBreakpointKindSet.of(TargetBreakpointKind.SW_EXECUTE);
		/*
		switch (from.getType()) {
			case BREAKPOINT:
				return TargetBreakpointKindSet.of(TargetBreakpointKind.SW_EXECUTE);
			case HW_BREAKPOINT:
				return TargetBreakpointKindSet.of(TargetBreakpointKind.HW_EXECUTE);
			case HW_WATCHPOINT:
				return TargetBreakpointKindSet.of(TargetBreakpointKind.WRITE);
			case READ_WATCHPOINT:
				return TargetBreakpointKindSet.of(TargetBreakpointKind.READ);
			case ACCESS_WATCHPOINT:
				return TargetBreakpointKindSet.of(TargetBreakpointKind.READ,
					TargetBreakpointKind.WRITE);
			default:
				return TargetBreakpointKindSet.of();
		}
		*/
	}

	@Override
	public TargetBreakpointKindSet getKinds() {
		return kinds;
	}

	@Override
	public void addAction(TargetBreakpointAction action) {
		actions.add(action);
	}

	@Override
	public void removeAction(TargetBreakpointAction action) {
		actions.remove(action);
	}

	protected CompletableFuture<Object> getInfo(boolean refresh) {
		SBTarget session = getManager().getCurrentSession();
		if (!refresh) {
			return CompletableFuture.completedFuture(getManager().getKnownBreakpoints(session).get(number));
		}
		return getManager().listBreakpoints(session)
				.thenApply(__ -> getManager().getKnownBreakpoints(session).get(number));
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		return getInfo(refresh).thenAccept(i -> {
			updateInfo(i, "Refreshed");
		});
	}

	@Override
	public CompletableFuture<Void> disable() {
		return getModel().gateFuture(getManager().disableBreakpoints(number));
	}

	@Override
	public CompletableFuture<Void> enable() {
		return getModel().gateFuture(getManager().enableBreakpoints(number));
	}

	public void updateInfo(Object info, String reason) {
		setModelObject(info);
		if (info instanceof SBWatchpoint) {
			updateWptInfo((SBWatchpoint)info, reason);
		}
		else {
			updateBktpInfo((SBBreakpoint)info, reason);
		}
	}

	protected void updateBktpInfo(SBBreakpoint info, String reason) {
		updateAttributesFromInfo(reason);
		getManager().listBreakpointLocations(info).thenAccept(byNumber -> {
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

	protected void updateWptInfo(SBWatchpoint info, String reason) {
		updateAttributesFromInfo(reason);		
	}

	protected LldbModelTargetBreakpointLocation findLocation(LldbModelTargetStackFrame frame) {
		/*
		for (LldbModelTargetBreakpointLocation bp : breaksBySub.values()) {
			if (!bp.loc.getInferiorIds().contains(frame.inferior.inferior.getId())) {
				continue;
			}
			return bp;
		}
		*/
		return null;
	}

	protected void breakpointHit(LldbModelTargetStackFrame frame,
			LldbModelTargetBreakpointLocation eb) {
		actions.fire.breakpointHit(this, frame.getParentThread(), frame, eb);
	}

	public synchronized LldbModelTargetBreakpointLocation getTargetBreakpointLocation(
			SBBreakpointLocation loc) {
		return breaksBySub.computeIfAbsent(loc.GetBreakpoint(),
			i -> new LldbModelTargetBreakpointLocationImpl(this, loc));
	}

	protected void updateAttributesFromInfo(String reason) {
		Object modelObject = getModelObject();
		if (modelObject instanceof SBBreakpoint) {
			SBBreakpoint bpt = (SBBreakpoint) modelObject;
			this.changeAttributes(List.of(), List.of(), Map.of( //
				DISPLAY_ATTRIBUTE_NAME, display = getDescription(0), //
				SPEC_ATTRIBUTE_NAME, this, //
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
		} else {
			
		}
	}

	@Override
	public String getDisplay() {
		return display;
	}

	@Override
	public Object getBreakpointInfo() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void setBreakpointId(String id) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public boolean isBreakpointEnabled() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public void setBreakpointEnabled(boolean enabled) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public ListenerSet<TargetBreakpointAction> getActions() {
		// TODO Auto-generated method stub
		return null;
	}

}
