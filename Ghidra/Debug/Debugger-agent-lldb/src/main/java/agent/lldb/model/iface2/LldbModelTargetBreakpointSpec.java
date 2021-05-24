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
package agent.lldb.model.iface2;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import SWIG.SBBreakpoint;
import SWIG.SBWatchpoint;
import agent.lldb.lldb.DebugClient;
import agent.lldb.model.iface1.LldbModelTargetBptHelper;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetBreakpointSpecContainer.TargetBreakpointKindSet;
import ghidra.program.model.address.*;

public interface LldbModelTargetBreakpointSpec extends //
		LldbModelTargetObject, //
		TargetBreakpointSpec, //
		TargetBreakpointLocation, //
		TargetDeletable, //
		LldbModelTargetBptHelper {

	String BPT_ACCESS_ATTRIBUTE_NAME = "Access";
	String BPT_DISP_ATTRIBUTE_NAME = "Enabled";
	String BPT_VALID_ATTRIBUTE_NAME = "Valid";
	String BPT_TIMES_ATTRIBUTE_NAME = "Count";
	String BPT_TYPE_ATTRIBUTE_NAME = "Type";
	String BPT_INDEX_ATTRIBUTE_NAME = "Id";

	@Override
	public default CompletableFuture<Void> delete() {
		return getModel().gateFuture(getManager().deleteBreakpoints(getNumber()));
	}

	@Override
	public default CompletableFuture<Void> disable() {
		setEnabled(false, "Disabled");
		return getModel().gateFuture(getManager().disableBreakpoints(getNumber()));
	}

	@Override
	public default CompletableFuture<Void> enable() {
		setEnabled(true, "Enabled");
		return getModel().gateFuture(getManager().enableBreakpoints(getNumber()));
	}

	@Override
	public default String getExpression() {
		return null; //getBreakpointInfo().getExpression();
	}

	public default long getNumber() {
		return Long.parseLong(DebugClient.getId(getBreakpointInfo()));
	}

	@Override
	public default TargetBreakpointKindSet getKinds() {
		Object modelObject = getModelObject();
		if (modelObject instanceof SBBreakpoint) {
			return TargetBreakpointKindSet.of(TargetBreakpointKind.SW_EXECUTE);
		} else {
			SBWatchpoint wpt = (SBWatchpoint) modelObject;
		}
		return TargetBreakpointKindSet.of();
	}

	public void updateInfo(Object info, String reason);

	/**
	 * Update the enabled field
	 * 
	 * This does not actually toggle the breakpoint. It just updates the field and calls the proper
	 * listeners. To actually toggle the breakpoint, use {@link #toggle(boolean)} instead, which if
	 * effective, should eventually cause this method to be called.
	 * 
	 * @param enabled true if enabled, false if disabled
	 * @param reason a description of the cause (not really used, yet)
	 */
	public default void setEnabled(boolean enabled, String reason) {
		setBreakpointEnabled(enabled);
		changeAttributes(List.of(), Map.of(ENABLED_ATTRIBUTE_NAME, enabled //
		), reason);
	}

	@Override
	public default boolean isEnabled() {
		return isBreakpointEnabled();
	}

	@Override
	public default void addAction(TargetBreakpointAction action) {
		getActions().add(action);
	}

	@Override
	public default void removeAction(TargetBreakpointAction action) {
		getActions().remove(action);
	}

	public default void breakpointHit() {
		LldbModelTargetThread targetThread =
			getParentProcess().getThreads().getTargetThread(getManager().getEventThread());
		getActions().fire.breakpointHit((LldbModelTargetBreakpointSpec) getProxy(), targetThread,
			null, this);
	}
	
}
