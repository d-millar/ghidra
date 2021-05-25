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
package agent.lldb.manager.cmd;

import SWIG.*;
import agent.lldb.manager.LldbCause;
import agent.lldb.manager.breakpoint.LldbBreakpointInfo;
import agent.lldb.manager.impl.LldbManagerImpl;

/**
 * Implementation of {@link DbgManagerImpl#deleteBreakpoints(long)}
 */
public class LldbDeleteBreakpointsCommand extends AbstractLldbCommand<Void> {

	private final String[] ids;

	public LldbDeleteBreakpointsCommand(LldbManagerImpl manager, String... ids) {
		super(manager);
		this.ids = ids;
	}

	@Override
	public Void complete(LldbPendingCommand<?> pending) {
		SBTarget currentSession = manager.getCurrentSession();
		for (String id : ids) {
			manager.doBreakpointDeleted(currentSession, id, pending);
		}
		return null;
	}

	@Override
	public void invoke() {
		SBTarget currentSession = manager.getCurrentSession();
		for (String id : ids) {
			Object info = manager.getBreakpoint(currentSession, id);
			if (info instanceof SBBreakpoint) {
				SBBreakpoint bpt = (SBBreakpoint) info;
				currentSession.BreakpointDelete(bpt.GetID());
				//manager.getEventListeners().fire.breakpointDeleted(bpt, LldbCause.Causes.UNCLAIMED);
			} else {
				SBWatchpoint wpt = (SBWatchpoint) info;
				currentSession.DeleteWatchpoint(wpt.GetID());
				//manager.getEventListeners().fire.breakpointDeleted(wpt, LldbCause.Causes.UNCLAIMED);
			}
		}
	}
}
