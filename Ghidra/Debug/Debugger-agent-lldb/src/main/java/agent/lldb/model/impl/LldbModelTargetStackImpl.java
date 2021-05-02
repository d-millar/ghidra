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

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import SWIG.SBFrame;
import agent.lldb.lldb.DebugClient;
import agent.lldb.model.iface2.LldbModelTargetProcess;
import agent.lldb.model.iface2.LldbModelTargetStack;
import agent.lldb.model.iface2.LldbModelTargetStackFrame;
import agent.lldb.model.iface2.LldbModelTargetThread;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetElementType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.util.Msg;
import ghidra.util.datastruct.WeakValueHashMap;

@TargetObjectSchemaInfo(
	name = "Stack",
	elements = {
		@TargetElementType(type = LldbModelTargetStackFrameImpl.class)
	},
	attributes = {
		@TargetAttributeType(type = Void.class)
	},
	canonicalContainer = true)
public class LldbModelTargetStackImpl extends LldbModelTargetObjectImpl
		implements LldbModelTargetStack {

	protected final LldbModelTargetThread thread;

	public static final String NAME = "Stack";

	protected final Map<Integer, LldbModelTargetStackFrameImpl> framesByLevel =
		new WeakValueHashMap<>();

	public LldbModelTargetStackImpl(LldbModelTargetThread thread, LldbModelTargetProcess process) {
		super(thread.getModel(), thread, NAME, "Stack");
		this.thread = thread;
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		return null; /*thread.getThread().listStackFrames().thenAccept(f -> {
			List<TargetObject> frames;
			synchronized (this) {
				frames = f.stream().map(this::getTargetFrame).collect(Collectors.toList());
			}
			// TODO: This might be a case where "move" is useful
			setElements(frames, Map.of(), "Refreshed");
		});
		*/
	}

	@Override
	public synchronized LldbModelTargetStackFrame getTargetFrame(SBFrame frame) {
		return null; /*framesByLevel.compute(frame.GetFrameID(), (l, f) -> {
			if (f == null) {
				return new LldbModelTargetStackFrameImpl(this, thread, frame);
			}
			f.setFrame(frame);
			return f;
		});
		*/
	}

	/*
	public void invalidateRegisterCaches() {
		setElements(List.of(), Map.of(), "Invalidated");
		for (LldbModelTargetStackFrameImpl frame : framesByLevel.values()) {
			frame.invalidateRegisterCaches();
		}
	}
	*/

	@Override
	public void onRunning() {
		// NB: We don't want to do this apparently
		//invalidateRegisterCaches();
		setAccessible(false);
	}

	@Override
	public void onStopped() {
		setAccessible(true);
		Integer id = DebugClient.getThreadId(thread.getThread());
		Integer eid =  DebugClient.getThreadId(getManager().getEventThread());
		if (id == eid) {
			update();
		}
	}

	/**
	 * Re-fetch the stack frames, generating events for updates
	 * 
	 * GDB doesn't produce stack change events, but they should only ever happen by running a
	 * target. Thus, every time we're STOPPED, this method should be called.
	 */
	@Override
	public void update() {
		requestElements(true).exceptionally(e -> {
			Msg.error(this, "Could not update stack " + this + " on STOPPED");
			return null;
		});
	}
}
