package org.openspaces.servicegrid;

import org.openspaces.servicegrid.model.tasks.Task;
import org.openspaces.servicegrid.model.tasks.TaskExecutorState;

public interface Orchestrator<S extends TaskExecutorState, T extends Task> extends TaskExecutor<S> {

	Iterable<T> orchestrate();

}
