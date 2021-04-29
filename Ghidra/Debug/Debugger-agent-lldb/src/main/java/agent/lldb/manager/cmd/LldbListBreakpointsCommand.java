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

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import agent.lldb.lldb.DebugBreakpoint;
import agent.lldb.manager.breakpoint.LldbBreakpointInfo;
import agent.lldb.manager.impl.LldbManagerImpl;


/**
 * Implementation of {@link LldbProcess#listBreakpoints()}
 */
public class LldbListBreakpointsCommand extends AbstractLldbCommand<Map<Long, LldbBreakpointInfo>> {

	private List<DebugBreakpoint> breakpoints;

	public LldbListBreakpointsCommand(LldbManagerImpl manager) {
		super(manager);
	}

	@Override
	public Map<Long, LldbBreakpointInfo> complete(LldbPendingCommand<?> pending) {
		Map<Long, LldbBreakpointInfo> list = new LinkedHashMap<>();
		for (DebugBreakpoint bpt : breakpoints) {
			LldbBreakpointInfo info = new LldbBreakpointInfo(bpt, manager.getCurrentProcess());
			list.put((long) bpt.getId(), info);
		}
		return list;
	}

	@Override
	public void invoke() {
		//breakpoints = manager.getControl().getBreakpoints();
	}
}
