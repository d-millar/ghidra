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

import agent.lldb.lldb.DebugBreakpoint;
import agent.lldb.lldb.DebugBreakpoint.BreakAccess;
import agent.lldb.lldb.DebugBreakpoint.BreakFlags;
import agent.lldb.lldb.DebugBreakpoint.BreakType;
import agent.lldb.manager.breakpoint.LldbBreakpointInfo;
import agent.lldb.manager.breakpoint.LldbBreakpointInsertions;
import agent.lldb.manager.breakpoint.LldbBreakpointType;
import agent.lldb.manager.impl.LldbManagerImpl;
import ghidra.comm.util.BitmaskSet;

/**
 * Implementation of {@link LldbBreakpointInsertions#insertBreakpoint(String)}
 */
public class LldbInsertBreakpointCommand extends AbstractLldbCommand<LldbBreakpointInfo> {
	//private List<Long> locations;
	private final LldbBreakpointType type;
	private LldbBreakpointInfo bkpt;
	private int len;
	private final String expression;
	private final Long loc;

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
		this.loc = loc;
	}

	@Override
	public LldbBreakpointInfo complete(LldbPendingCommand<?> pending) {
		//manager.doBreakpointCreated(bkpt, pending);
		return bkpt;
	}

	@Override
	public void invoke() {
		/*
		DebugControl control = manager.getControl();
		BreakType bt = BreakType.DATA;
		if (type.equals(LldbBreakpointType.BREAKPOINT)) {
			bt = BreakType.CODE;
		}
		// 2 for BU, 1 for BP
		DebugBreakpoint bp = control.addBreakpoint(bt);
		if (bt.equals(BreakType.DATA)) {
			BitmaskSet<BreakAccess> access = BitmaskSet.of(BreakAccess.EXECUTE);
			if (type.equals(LldbBreakpointType.ACCESS_WATCHPOINT)) {
				access = BitmaskSet.of(BreakAccess.READ, BreakAccess.WRITE);
			}
			if (type.equals(LldbBreakpointType.READ_WATCHPOINT)) {
				access = BitmaskSet.of(BreakAccess.READ);
			}
			if (type.equals(LldbBreakpointType.HW_WATCHPOINT)) {
				access = BitmaskSet.of(BreakAccess.WRITE);
			}
			if (type.equals(LldbBreakpointType.HW_BREAKPOINT)) {
				access = BitmaskSet.of(BreakAccess.EXECUTE);
				len = 1;
			}
			bp.setDataParameters(len, access);
		}
		if (loc != null) {
			bp.setOffset(loc);
		}
		else {
			bp.setOffsetExpression(expression);
		}
		bp.addFlags(BreakFlags.ENABLED);

		bkpt = new LldbBreakpointInfo(bp, manager.getCurrentProcess());
		*/
	}
}
