/**
 * Copyright 2016-2018 The Reaktivity Project
 *
 * The Reaktivity Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package org.reaktivity.command.log.internal;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Stream;

import org.agrona.LangUtil;
import org.agrona.concurrent.status.CountersManager;
import org.reaktivity.command.log.internal.layouts.ControlLayout;
import org.reaktivity.reaktor.internal.ReaktorConfiguration;

public final class LogCountersCommand implements Runnable
{
    private final Path directory;
    private final boolean verbose;
    private final boolean separator;
    private final Logger out;
    private final Map<Path, CountersManager> countersByPath;

    LogCountersCommand(
        ReaktorConfiguration config,
        Logger out,
        boolean verbose,
        boolean separator)
    {
        this.directory = config.directory();
        this.verbose = verbose;
        this.separator = separator;
        this.out = out;
        this.countersByPath = new LinkedHashMap<>();
    }

    private boolean isControlFile(
        Path path)
    {
        return path.getNameCount() - directory.getNameCount() == 2 &&
               "control".equals(path.getName(path.getNameCount() - 1).toString()) &&
               Files.isRegularFile(path);
    }

    private void onDiscovered(
        Path path)
    {
        if (verbose)
        {
            out.printf("Discovered: %s\n", path);
        }
    }

    private void counters(
        Path controlPath)
    {
        String owner = controlPath.getName(controlPath.getNameCount() - 2).toString();
        CountersManager manager = countersByPath.computeIfAbsent(controlPath, this::newCountersManager);
        final String valueFormat = separator ? ",d" : "d";

        manager.forEach((id, name) -> out.printf(
                "{" +
                "\"name\": \"%s.%s\"," +
                "\"value\":%" + valueFormat +
                "}\n", owner, name, manager.getCounterValue(id)));
    }

    private CountersManager newCountersManager(Path path)
    {
        ControlLayout layout = new ControlLayout.Builder()
                .controlPath(path)
                .readonly(true)
                .build();

        return new CountersManager(layout.counterLabelsBuffer(), layout.counterValuesBuffer());
    }

    @Override
    public void run()
    {
        try (Stream<Path> files = Files.walk(directory, 2))
        {
            files.filter(this::isControlFile)
                 .peek(this::onDiscovered)
                 .forEach(this::counters);
            out.printf("\n");
        }
        catch (IOException ex)
        {
            LangUtil.rethrowUnchecked(ex);
        }
    }
}
