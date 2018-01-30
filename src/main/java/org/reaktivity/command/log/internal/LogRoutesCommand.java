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

import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.stream.Collectors.toList;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;

import org.agrona.LangUtil;
import org.agrona.concurrent.BackoffIdleStrategy;
import org.agrona.concurrent.IdleStrategy;
import org.reaktivity.command.log.internal.layouts.RoutesLayout;
import org.reaktivity.nukleus.Configuration;

public class LogRoutesCommand
{

    public static final String ROUTES_BUFFER_CAPACITY_PROPERTY_NAME = "reaktor.routes.buffer.capacity";
    public static final int ROUTES_BUFFER_CAPACITY_DEFAULT = 1024 * 1024;

    private static final long MAX_PARK_NS = MILLISECONDS.toNanos(100L);
    private static final long MIN_PARK_NS = MILLISECONDS.toNanos(1L);
    private static final int MAX_YIELDS = 300;
    private static final int MAX_SPINS = 200;

    private final Path directory;
    private final boolean verbose;
    private final int routesCapacity;
    private final Logger out;
    private final ConfigurationUtil configUtil = new ConfigurationUtil();
    private final IdleStrategy idleStrategy = new BackoffIdleStrategy(MAX_SPINS, MAX_YIELDS, MIN_PARK_NS, MAX_PARK_NS);


    LogRoutesCommand(
        Configuration config,
        Logger out,
        boolean verbose)
    {
        this.directory = config.directory();
        this.verbose = verbose;
        this.routesCapacity = configUtil.getInteger(ROUTES_BUFFER_CAPACITY_PROPERTY_NAME, ROUTES_BUFFER_CAPACITY_DEFAULT);
        this.out = out;
    }

    private boolean isRoutesFile(
        Path path)
    {
        return path.getNameCount() - directory.getNameCount() == 2 &&
               "routes".equals(path.getName(path.getNameCount() - 1).toString()) &&
               Files.isRegularFile(path);
    }

    private LoggableRoutes newLoggable(
        Path path)
    {

        RoutesLayout layout = new RoutesLayout.Builder()
                .routesPath(path)
                .routesBufferCapacity(routesCapacity)
                .build();

        String nukleusName = path.getName(path.getNameCount() - 2).toString();

        return new LoggableRoutes(layout, nukleusName, out, idleStrategy);
    }

    private void onDiscovered(
        Path path)
    {
        if (verbose)
        {
            out.printf("Discovered: %s\n", path);
        }
    }

    void invoke()
    {
        try (Stream<Path> files = Files.walk(directory, 2))
        {
        LoggableRoutes[] loggables = files.filter(this::isRoutesFile)
             .peek(this::onDiscovered)
             .map(this::newLoggable)
             .collect(toList())
             .toArray(new LoggableRoutes[0]);

            for (int i=0; i < loggables.length; i++)
            {
                loggables[i].process();
            }

        }
        catch (IOException ex)
        {
            LangUtil.rethrowUnchecked(ex);
        }
    }

}
