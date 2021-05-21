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
package agent.lldb.manager.breakpoint;

import java.util.Objects;

import SWIG.SBProcess;
import SWIG.SBWatchpoint;
import agent.lldb.lldb.DebugClient;

public class LldbWatchpointInfo extends LldbBreakpointInfo {

	private SBWatchpoint wpt;
	private SBProcess proc;

	/**
	 * Construct Dbg breakpoint information
	 */

	public LldbWatchpointInfo(SBWatchpoint wpt, SBProcess process) {
		super(null, process);
		this.wpt = wpt;
		this.proc = process;
	}

	@Override
	public int hashCode() {
		return Objects.hash(wpt.GetID());
	}

	@Override
	public String toString() {
		return DebugClient.getId(wpt);
	}
	/*
	@Override
	public String toString() {
		return "<DbgBreakpointInfo number=" + number + ",type=" + getType() + ",flags=" +
			getFlags() + ",addr=" + location + ",times=" + getTimes() + ",size=" + getSize() +
			",access=" + getAccess() + ">";
	}
	*/

	@Override
	public boolean equals(Object obj) {
		if (!((obj instanceof LldbWatchpointInfo))) {
			return false;
		}
		LldbWatchpointInfo that = (LldbWatchpointInfo) obj;
		if (this.wpt.GetID() != that.wpt.GetID()) {
			return false;
		}
		return true;
	}

	/**
	 * Get the breakpoint disposition, i.e., what happens to the breakpoint once it has been hit
	 * 
	 * @return the disposition
	 */
	public LldbBreakpointDisp getDisp() {
		return LldbBreakpointDisp.KEEP;
	}

	/**
	 * Get the size of the breakpoint
	 * 
	 * @return the size
	 */
	public int getSize() {
		return (int) wpt.GetWatchSize();
	}


	/**
	 * Get the offset of this breakpoint
	 * 
	 * <p>
	 * Note if the offset was given as an expression, but it hasn't been resolved, this will return
	 * {@code null}.
	 * 
	 * @return the offset, or {@code null}
	 */
	public Long getOffset() {
		return wpt.GetWatchAddress().longValue();
	}

	/**
	 * Check if the breakpoint is enabled
	 * 
	 * @return true if enabled, false otherwise
	 */
	public boolean isEnabled() {
		return wpt.IsEnabled();
	}

	/**
	 * Get the number of times the breakpoint has been hit
	 * 
	 * @return the hit count
	 */
	public int getTimes() {
		return (int) wpt.GetHitCount();
	}

	/*
	public SBBreakpoint withEnabled(@SuppressWarnings("hiding") boolean enabled) {
		if (isEnabled() == enabled) {
			return bpt;
		}
		return new bpt(bpt, enabled);
	}
	*/

	public SBWatchpoint getWatchpoint() {
		return wpt;
	}

	public void setWatchoint(SBWatchpoint wpt) {
		this.wpt = wpt;
	}

	public SBProcess getProc() {
		return proc;
	}

}
