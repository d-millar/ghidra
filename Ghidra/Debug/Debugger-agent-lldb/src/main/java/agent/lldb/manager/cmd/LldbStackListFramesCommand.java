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

import java.util.List;

import SWIG.SBFrame;
import SWIG.SBThread;
import agent.lldb.manager.impl.LldbManagerImpl;

public class LldbStackListFramesCommand extends AbstractLldbCommand<List<SBFrame>> {
	protected final SBThread thread;
	private List<SBFrame> result;

	public LldbStackListFramesCommand(LldbManagerImpl manager, SBThread thread) {
		super(manager);
		this.thread = thread;
	}

	@Override
	public List<SBFrame> complete(LldbPendingCommand<?> pending) {
		return result;
	}

	@Override
	public void invoke() {
		/*
		result = new ArrayList<>();
		DebugSystemObjects so = manager.getSystemObjects();
		DebugThreadId previous = so.getCurrentThreadId();
		so.setCurrentThreadId(thread.getId());
		DebugStackInformation stackTrace = manager.getControl().getStackTrace(0L, 0L, 0L);
		for (int i = 0; i < stackTrace.getNumberOfFrames(); i++) {
			DEBUG_STACK_FRAME tf = stackTrace.getFrame(i);
			//DbgStackFrame frame = new DbgStackFrameImpl(thread, tf.FrameNumber.intValue(),
			//	new BigInteger(Long.toHexString(tf.InstructionOffset.longValue()), 16), null);
			SBFrame frame = new SBFrame(thread, //
				tf.FrameNumber.intValue(), //
				new BigInteger(Long.toHexString(tf.InstructionOffset.longValue()), 16), //
				tf.FuncTableEntry.longValue(), //
				tf.FrameOffset.longValue(), //
				tf.ReturnOffset.longValue(), //
				tf.StackOffset.longValue(), //
				tf.Virtual.booleanValue(), //
				tf.Params[0].longValue(), //
				tf.Params[1].longValue(), //
				tf.Params[2].longValue(), //
				tf.Params[3].longValue());
			result.add(frame);
		}
		*/
		//so.setCurrentThreadId(previous);
	}
}
