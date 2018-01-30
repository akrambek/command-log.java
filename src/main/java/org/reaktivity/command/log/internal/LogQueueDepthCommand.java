/**
 * Copyright 2016-2017 The Reaktivity Project
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

import org.agrona.LangUtil;
import org.reaktivity.command.log.internal.layouts.StreamsLayout;
import org.reaktivity.command.log.internal.spy.RingBufferSpy;
import org.reaktivity.nukleus.Configuration;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;

public final class LogQueueDepthCommand
{
    private final Path directory;
    private final boolean verbose;
    private final Logger out;

    private final long streamsCapacity;
    private final long throttleCapacity;

    public LogQueueDepthCommand(
        Configuration config,
        Logger out,
        boolean verbose)
    {
        this.directory = config.directory();
        this.out = out;
        this.verbose = verbose;
        this.streamsCapacity = config.streamsBufferCapacity();
        this.throttleCapacity = config.throttleBufferCapacity();
    }

    private boolean isStreamsFile(
        Path path)
    {
        return path.getNameCount() - directory.getNameCount() == 3 &&
                "streams".equals(path.getName(path.getNameCount() - 2).toString()) &&
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

    private void displayQueueDepth(
        Path path)
    {
        try (StreamsLayout layout = new StreamsLayout.Builder()
                .path(path)
                .streamsCapacity(streamsCapacity)
                .throttleCapacity(throttleCapacity)
                .readonly(true)
                .build();
        )
        {
            String name = path.getName(path.getNameCount() - 1).toString();
            displayQueueDepth(name, "streams", layout.streamsBuffer());
            displayQueueDepth(name, "throttle", layout.throttleBuffer());
        }
    }

    private void displayQueueDepth(
        String name,
        String type,
        RingBufferSpy buffer)
    {
        // read consumer position first for pessimistic queue depth
        long consumerAt = buffer.consumerPosition();
        long producerAt = buffer.producerPosition();

        out.printf("%s.%s %d\n ", name, type, producerAt - consumerAt);
    }

    void invoke()
    {
        try (Stream<Path> files = Files.walk(directory, 3))
        {
            files.filter(this::isStreamsFile)
                    .peek(this::onDiscovered)
                    .forEach(this::displayQueueDepth);
        }
        catch (IOException ex)
        {
            LangUtil.rethrowUnchecked(ex);
        }
    }
}
