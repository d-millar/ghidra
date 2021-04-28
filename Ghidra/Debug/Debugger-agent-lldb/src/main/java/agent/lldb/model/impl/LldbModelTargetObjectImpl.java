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

import SWIG.StateType;
import agent.lldb.manager.LldbCause;
import agent.lldb.manager.LldbStateListener;
import agent.lldb.model.AbstractLldbModel;
import agent.lldb.model.iface1.LldbModelTargetAccessConditioned;
import agent.lldb.model.iface1.LldbModelTargetExecutionStateful;
import agent.lldb.model.iface2.LldbModelTargetObject;
import agent.lldb.model.iface2.LldbModelTargetProcess;
import agent.lldb.model.iface2.LldbModelTargetSession;
import agent.lldb.model.iface2.LldbModelTargetThread;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetAccessConditioned;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetProcess;
import ghidra.dbg.target.TargetThread;
import ghidra.dbg.target.schema.TargetObjectSchema;

public class LldbModelTargetObjectImpl extends DefaultTargetObject<TargetObject, TargetObject>
		implements LldbModelTargetObject {

	protected boolean accessible = true;
	protected final LldbStateListener accessListener = this::checkExited;
	private boolean modified;

	public LldbModelTargetObjectImpl(AbstractLldbModel impl, TargetObject parent, String name,
			String typeHint) {
		super(impl, parent, name, typeHint);
		getManager().addStateListener(accessListener);
	}

	public LldbModelTargetObjectImpl(AbstractLldbModel impl, TargetObject parent, String name,
			String typeHint, TargetObjectSchema schema) {
		super(impl, parent, name, typeHint, schema);
		getManager().addStateListener(accessListener);
	}

	public void setAttribute(String key, String value) {
		changeAttributes(List.of(), List.of(), Map.of( //
			key, value), "Initialized");
	}

	@Override
	protected void doInvalidate(TargetObject branch, String reason) {
		super.doInvalidate(branch, reason);
		getManager().removeStateListener(accessListener);
	}

	public void setAccessible(boolean accessible) {
		synchronized (attributes) {
			if (this.accessible == accessible) {
				return;
			}
			this.accessible = accessible;
		}
		if (this instanceof LldbModelTargetAccessConditioned) {
			changeAttributes(List.of(), List.of(), Map.of( //
				TargetAccessConditioned.ACCESSIBLE_ATTRIBUTE_NAME, accessible //
			), "Accessibility changed");
		}
	}

	@Override
	public AbstractLldbModel getModel() {
		return (AbstractLldbModel) model;
	}

	public void onRunning() {
		setAccessible(false);
	}

	public void onStopped() {
		setAccessible(true);
		update();
	}

	public void onExit() {
		setAccessible(true);
	}

	protected void update() {
		Map<String, ?> existingAttributes = getCachedAttributes();
		Boolean autoupdate = (Boolean) existingAttributes.get("autoupdate");
		if (autoupdate != null && autoupdate) {
			requestAttributes(true);
			requestElements(true);
		}
	}

	protected void checkExited(StateType state, LldbCause cause) {
		TargetExecutionState exec = TargetExecutionState.INACTIVE;
		switch (state.swigValue()) {
			case eStateInvalid: {
				exec = TargetExecutionState.INACTIVE;
				break;
			}
			case eStateConnected: {
				exec = TargetExecutionState.ALIVE;
				break;
			}
			case RUNNING: {
				exec = TargetExecutionState.RUNNING;
				resetModified();
				onRunning();
				break;
			}
			case STOPPED: {
				exec = TargetExecutionState.STOPPED;
				onStopped();
				break;
			}
			case EXIT: {
				exec = TargetExecutionState.TERMINATED;
				if (getParentProcess() != null || this instanceof TargetProcess) {
					getManager().removeStateListener(accessListener);
				}
				onExit();
				break;
			}
			case SESSION_EXIT: {
				getModel().close();
				return;
			}
		}
		if (this instanceof LldbModelTargetExecutionStateful) {
			LldbModelTargetExecutionStateful stateful = (LldbModelTargetExecutionStateful) this;
			stateful.setExecutionState(exec, "Refreshed");
		}
	}

	@Override
	public CompletableFuture<? extends Map<String, ?>> requestNativeAttributes() {
		throw new AssertionError();  // shouldn't ever be here
	}

	@Override
	public CompletableFuture<List<TargetObject>> requestNativeElements() {
		throw new AssertionError();  // shouldn't ever be here
	}

	@Override
	public LldbModelTargetSession getParentSession() {
		LldbModelTargetObject test = (LldbModelTargetObject) parent;
		while (test != null && !(test instanceof LldbModelTargetSession)) {
			test = (LldbModelTargetObject) test.getParent();
		}
		return test == null ? null : (LldbModelTargetSession) test;
	}

	@Override
	public LldbModelTargetProcess getParentProcess() {
		LldbModelTargetObject test = (LldbModelTargetObject) parent;
		while (test != null && !(test instanceof TargetProcess)) {
			test = (LldbModelTargetObject) test.getParent();
		}
		return test == null ? null : (LldbModelTargetProcess) test;
	}

	@Override
	public LldbModelTargetThread getParentThread() {
		LldbModelTargetObject test = (LldbModelTargetObject) parent;
		while (test != null && !(test instanceof TargetThread)) {
			test = (LldbModelTargetObject) test.getParent();
		}
		return test == null ? null : (LldbModelTargetThread) test;
	}

	@Override
	public void setModified(Map<String, Object> map, boolean b) {
		if (modified) {
			map.put(MODIFIED_ATTRIBUTE_NAME, modified);
		}
	}

	@Override
	public void setModified(boolean modified) {
		if (modified) {
			changeAttributes(List.of(), List.of(), Map.of( //
				MODIFIED_ATTRIBUTE_NAME, modified //
			), "Refreshed");
		}
	}

	@Override
	public void resetModified() {
		changeAttributes(List.of(), List.of(), Map.of( //
			MODIFIED_ATTRIBUTE_NAME, false //
		), "Refreshed");
	}

	public TargetObject searchForSuitable(Class<? extends TargetObject> type) {
		List<String> pathToClass = model.getRootSchema().searchForSuitable(type, path);
		return model.getModelObject(pathToClass);
	}

}
