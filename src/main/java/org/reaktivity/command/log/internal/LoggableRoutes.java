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

import static java.lang.String.format;

import java.util.concurrent.atomic.AtomicInteger;

import org.agrona.DirectBuffer;
import org.agrona.MutableDirectBuffer;
import org.agrona.collections.LongHashSet;
import org.agrona.concurrent.IdleStrategy;
import org.agrona.concurrent.UnsafeBuffer;
import org.reaktivity.command.log.internal.layouts.RoutesLayout;
import org.reaktivity.command.log.internal.types.OctetsFW;
import org.reaktivity.command.log.internal.types.control.RouteFW;
import org.reaktivity.command.log.internal.types.state.RouteTableFW;

public final class LoggableRoutes implements AutoCloseable
{
    private final RoutesLayout layout;
    private final MutableDirectBuffer routesBuffer;
    private final Logger out;
    private final IdleStrategy idleStrategy;
    private final RouteTableFW routeTableRO;
    private final byte[] copyBuf;
    private final int capacity;
    private final UnsafeBuffer copyBufFW;
    private final RouteFW routeRO;
    private final LongHashSet loggedRoutes;
    private final String nukleusName;

    LoggableRoutes(
        RoutesLayout layout,
        String nukleusName,
        Logger logger,
        IdleStrategy idleStrategy)
    {
        this.layout = layout;
        this.nukleusName  = nukleusName;
        this.routesBuffer = layout.routesBuffer();
        this.out = logger;
        this.idleStrategy = idleStrategy;
        this.routeTableRO = new RouteTableFW();
        this.capacity = layout.capacity();
        this.copyBuf = new byte[capacity];
        this.copyBufFW = new UnsafeBuffer(copyBuf);
        this.routeRO = new RouteFW();
        this.loggedRoutes = new LongHashSet(-1);
    }

    int process()
    {
        RouteTableFW routeTable = routeTableRO.wrap(routesBuffer, 0, capacity);
        final int beforeAcquires = routeTableRO.writeLockAcquires();
        if (beforeAcquires == routeTableRO.writeLockReleases())
        {
            routesBuffer.getBytes(0, copyBuf);
            copyBufFW.wrap(copyBuf);
            routeTable = routeTableRO.wrap(copyBufFW, 0, capacity);
            final int afterCopyAcquires = routeTable.writeLockAcquires();
            if (beforeAcquires == afterCopyAcquires)
            {
                return logRoutes(routeTable, new LongHashSet(-1), new AtomicInteger(0));
            }
        }
        idleStrategy.idle();
        return process();
    }

    private int logRoutes(
        RouteTableFW routeTable,
        LongHashSet thisIterationRoutes,
        AtomicInteger workCnt)
    {
        routeTable.routeEntries().forEach(e ->
        {
            final OctetsFW routeOctets = e.route();
            final DirectBuffer buffer = routeOctets.buffer();
            final int offset = routeOctets.offset();
            final int routeSize = (int) e.routeSize();
            RouteFW route = routeRO.wrap(buffer, offset, offset + routeSize);

            final long correlationId = route.correlationId();
            final String role = route.role().toString();
            final String source = route.source().asString();
            final long sourceRef = route.sourceRef();
            final String target = route.target().asString();
            final long targetRef = route.targetRef();
            final long authorization = route.authorization();
            thisIterationRoutes.add(correlationId);

            if (!loggedRoutes.contains(correlationId))
            {
                workCnt.incrementAndGet();
                out.printf(format("%15s   %-10s %-20s [0x%016X] %-20s [0x%016X] [0x%016X]\n",
                                format("%s#%d", nukleusName, correlationId),
                                role,
                                source,
                                sourceRef,
                                target,
                                targetRef,
                                authorization));
                loggedRoutes.add(correlationId);
                workCnt.incrementAndGet();
            }
        });

        LongHashSet removedRoutes = loggedRoutes.difference(thisIterationRoutes);
        if (removedRoutes != null)
        {
            removedRoutes.stream().forEach(correlationId ->
            {
                out.printf(format("Unrouted %s#%d\n", nukleusName, correlationId));
                loggedRoutes.remove(correlationId);
            });
        }
        return workCnt.get();
    }

    @Override
    public void close() throws Exception
    {
        layout.close();
    }

}
