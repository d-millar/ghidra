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

import java.math.BigInteger;

import SWIG.*;
import agent.lldb.manager.LldbCause;
import agent.lldb.manager.breakpoint.*;
import agent.lldb.manager.impl.LldbManagerImpl;

/**
 * Implementation of {@link LldbBreakpointInsertions#insertBreakpoint(String)}
 */
public class LldbInsertBreakpointCommand extends AbstractLldbCommand<LldbBreakpointInfo> {
	//private List<Long> locations;
	private final LldbBreakpointType type;
	private LldbBreakpointInfo bkpt;
	private int len;
	private final String expression;
	private final BigInteger loc;

	public LldbInsertBreakpointCommand(LldbManagerImpl manager, String expression,
			LldbBreakpointType type) {
		super(manager);
		this.type = type;
		this.expression = expression;
		this.loc = null;
	}

	public LldbInsertBreakpointCommand(LldbManagerImpl manager, long loc, int len,
			LldbBreakpointType type) {
		super(manager);
		this.len = len;
		this.type = type;
		this.expression = null;
		this.loc = BigInteger.valueOf(loc);
	}

	@Override
	public LldbBreakpointInfo complete(LldbPendingCommand<?> pending) {
		SBTarget currentSession = manager.getCurrentSession();
		manager.doBreakpointCreated(currentSession, bkpt.getBreakpoint(), pending);
		return bkpt;
	}

	@Override
	public void invoke() {
		SBTarget currentSession = manager.getCurrentSession();
		if (type.equals(LldbBreakpointType.BREAKPOINT)) {
			SBBreakpoint bpt;
			if (loc != null) {
				bpt = currentSession.BreakpointCreateByAddress(loc);
			} else {
				bpt = currentSession.BreakpointCreateByRegex(expression);
			}
			bpt.SetEnabled(true);
			bkpt = new LldbBreakpointInfo(bpt, manager.getCurrentProcess());
			//manager.getEventListeners().fire.breakpointCreated(bpt, LldbCause.Causes.UNCLAIMED);
		} else {
			boolean read = false;
			boolean write = false;
			SBError error = new SBError();
			if (type.equals(LldbBreakpointType.ACCESS_WATCHPOINT)) {
				read = write = true;
			}
			if (type.equals(LldbBreakpointType.READ_WATCHPOINT)) {
				read = true;
			}
			if (type.equals(LldbBreakpointType.HW_WATCHPOINT)) {
				write = true;
			}
			if (type.equals(LldbBreakpointType.HW_BREAKPOINT)) {
				len = 1;
			}
			SBWatchpoint wpt = currentSession.WatchAddress(loc, len, read, write, error);	
			wpt.SetEnabled(true);
			bkpt = new LldbWatchpointInfo(wpt, manager.getCurrentProcess());
			//manager.getEventListeners().fire.breakpointCreated(wpt, LldbCause.Causes.UNCLAIMED);
		}
	}
}
