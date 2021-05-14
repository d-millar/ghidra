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
package agent.lldb.manager;

import SWIG.SBFrame;
import SWIG.SBProcess;
import SWIG.SBTarget;
import SWIG.SBThread;
import SWIG.StateType;
import agent.lldb.lldb.DebugModuleInfo;
import agent.lldb.manager.breakpoint.LldbBreakpointInfo;

public interface LldbEventsListenerAdapter extends LldbEventsListener {

	@Override
	public default void sessionAdded(SBTarget session, LldbCause cause) {
		// Extension point
	}

	@Override
	public default void sessionRemoved(Integer sessionId, LldbCause cause) {
		// Extension point
	}

	@Override
	public default void sessionSelected(SBTarget session, LldbCause cause) {
		// Extension point
	}

	@Override
	public default void processAdded(SBProcess process, LldbCause cause) {
		// Extension point
	}

	@Override
	public default void processRemoved(Integer processId, LldbCause cause) {
		// Extension point
	}

	@Override
	public default void processSelected(SBProcess process, LldbCause cause) {
		// Extension point
	}

	@Override
	public default void processStarted(SBProcess process, LldbCause cause) {
		// Extension point
	}

	@Override
	public default void processExited(SBProcess process, LldbCause cause) {
		// Extension point
	}

	@Override
	public default void threadCreated(SBThread thread, LldbCause cause) {
		// Extension point
	}

	@Override
	public default void threadStateChanged(SBThread thread, StateType state, LldbCause cause,
			LldbReason reason) {
		// Extension point
	}

	@Override
	public default void threadExited(Integer threadId, SBProcess process, LldbCause cause) {
		// Extension point

	}

	@Override
	public default void threadSelected(SBThread thread, SBFrame frame, LldbCause cause) {
		// Extension point
	}

	@Override
	public default void moduleLoaded(SBProcess process, DebugModuleInfo info, int index, LldbCause cause) {
		// Extension point
	}

	@Override
	public default void moduleUnloaded(SBProcess process, DebugModuleInfo info, int index, LldbCause cause) {
		// Extension point
	}

	@Override
	public default void breakpointCreated(LldbBreakpointInfo info, LldbCause cause) {
		// Extension point
	}

	@Override
	public default void breakpointModified(LldbBreakpointInfo newInfo, LldbBreakpointInfo oldInfo,
			LldbCause cause) {
		// Extension point
	}

	@Override
	public default void breakpointDeleted(LldbBreakpointInfo info, LldbCause cause) {
		// Extension point
	}

	@Override
	public default void breakpointHit(LldbBreakpointInfo info, LldbCause cause) {
		// Extension point
	}

	/*
	@Override
	public default void effectiveBreakpointCreated(DbgProcess process,
			DbgEffectiveBreakpoint newBkpt, DbgCause cause) {
		// Extension point
	}
	
	@Override
	public default void effectiveBreakpointModified(DbgProcess process,
			DbgEffectiveBreakpoint newBkpt, DbgEffectiveBreakpoint oldBkpt, DbgCause cause) {
		// Extension point
	}
	
	@Override
	public default void effectiveBreakpointDeleted(DbgProcess process,
			DbgEffectiveBreakpoint oldBkpt, DbgCause cause) {
		// Extension point
	}
	*/

	@Override
	public default void memoryChanged(SBProcess process, long addr, int len, LldbCause cause) {
		// Extension point
	}

	@Override
	public default void consoleOutput(String output, int mask) {
		// Extension point
	}

	@Override
	public default void promptChanged(String prompt) {
		// Extension point
	}

}
