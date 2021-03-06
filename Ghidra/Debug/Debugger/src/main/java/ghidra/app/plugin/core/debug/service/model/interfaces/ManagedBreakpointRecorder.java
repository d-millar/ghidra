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
package ghidra.app.plugin.core.debug.service.model.interfaces;

import java.util.Set;

import ghidra.dbg.target.*;
import ghidra.program.model.address.Address;
import ghidra.trace.model.breakpoint.TraceBreakpoint;
import ghidra.trace.model.thread.TraceThread;

public interface ManagedBreakpointRecorder {

	void offerBreakpointContainer(TargetBreakpointSpecContainer added);

	void offerBreakpointLocation(TargetObject target, TargetBreakpointLocation added);

	void recordBreakpoint(TargetBreakpointLocation loc, Set<TraceThread> traceThreads);

	void removeBreakpointLocation(TargetBreakpointLocation removed);

	TargetBreakpointSpecContainer getBreakpointContainer();

	TraceBreakpoint getTraceBreakpoint(TargetBreakpointLocation bpt);

	/**
	 * The length of a breakpoint location has changed
	 * 
	 * @param length the new length
	 * @param traceAddr the address of the location in the trace
	 * @param path the dot-separated path of the breakpoint location in the model
	 */
	void breakpointLocationChanged(int length, Address traceAddr, String path);

	void breakpointToggled(TargetBreakpointSpec spec, boolean enabled);
}
