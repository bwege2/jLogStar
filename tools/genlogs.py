#!/usr/bin/env python3
"""genlogs.py - synthetic Java/WildFly log generator with known, injected incidents.

Generates realistic WildFly server logs (daily rotated), a log4j2 application log, a small
console log and a ground_truth.json that describes every injected incident, so that a log
analyzer's error grouping / anomaly detection can be verified.

    python3 tools/genlogs.py --out DIR --size 500M --days 3 --seed 42 [--gzip-rotated]

Python 3.8+, standard library only. See tools/README-genlogs.md.
"""

import argparse
import datetime as dt
import gzip
import json
import math
import os
import random
import re
import sys
import time
from operator import itemgetter

WF_PRODUCT = 'WildFly Full 31.0.1.Final (WildFly Core 23.0.3.Final)'
LVL = {'TRACE': 'TRACE', 'DEBUG': 'DEBUG', 'INFO': 'INFO ', 'WARN': 'WARN ',
       'ERROR': 'ERROR', 'FATAL': 'FATAL'}
MS = ['%03d' % i for i in range(1000)]
HMS = ['%02d:%02d:%02d' % (i // 3600, i // 60 % 60, i % 60) for i in range(86400)]
TS_LEN = 23  # len('2026-11-20 10:23:45,123')
NUL = '\x00'  # inside a pool entry: "start another record with the same timestamp here"

# ======================================================================================
# stack frames
# ======================================================================================
MOD = {
    'UT': 'io.undertow.core@2.3.12.Final//',
    'UTS': 'io.undertow.servlet@2.3.12.Final//',
    'WFUT': 'org.wildfly.extension.undertow@31.0.1.Final//',
    'THR': 'org.jboss.threads@2.4.0.Final//',
    'XNIO': 'org.jboss.xnio@3.8.12.Final//',
    'XNION': 'org.jboss.xnio.nio@3.8.12.Final//',
    'JB': 'java.base/',
    'SERV': 'jakarta.servlet.api@6.0.0//',
    'RE': 'org.jboss.resteasy.resteasy-core@6.2.7.Final//',
    'REC': 'org.jboss.resteasy.resteasy-client@6.2.7.Final//',
    'EE': 'org.jboss.as.ee@31.0.1.Final//',
    'INV': 'org.jboss.invocation@2.0.1.Final//',
    'EJB': 'org.jboss.as.ejb3@31.0.1.Final//',
    'WELD': 'org.jboss.as.weld.common@31.0.1.Final//',
    'WELDE': 'org.jboss.weld.core@5.1.2.Final//',
    'JPA': 'org.jboss.as.jpa@31.0.1.Final//',
    'HIB': 'org.hibernate@6.4.4.Final//',
    'PG': 'org.postgresql@42.7.2//',
    'IJ': 'org.jboss.ironjacamar.impl@3.0.6.Final//',
    'IJA': 'org.jboss.ironjacamar.jdbcadapters@3.0.6.Final//',
    'ASC': 'org.jboss.as.connector@31.0.1.Final//',
    'TXN': 'org.jboss.jts@7.0.0.Final//',
    'WFTC': 'org.wildfly.transaction.client@3.0.5.Final//',
    'HC': 'org.apache.httpcomponents@4.5.14//',
    'ISPN': 'org.infinispan.core@14.0.24.Final//',
    'CLU': 'org.wildfly.clustering.web.infinispan@31.0.1.Final//',
    'MAIL': 'org.eclipse.angus.mail@2.0.2//',
    'APP': 'deployment.shop.war//',
}


def F(spec):
    """Parse 'MOD fq.Class.method:LINE' lines (LINE may be U=Unknown Source, N=Native Method)."""
    out = []
    for raw in spec.strip().splitlines():
        raw = raw.strip()
        if not raw:
            continue
        mod, rest = raw.split(' ', 1)
        meth, line = rest.rsplit(':', 1)
        simple = meth.rsplit('.', 1)[0].rsplit('.', 1)[-1].split('$', 1)[0]
        if line == 'U':
            loc = 'Unknown Source'
        elif line == 'N':
            loc = 'Native Method'
        else:
            loc = '%s.java:%s' % (simple, line)
        out.append((MOD[mod], meth, loc))
    return out


def A(*specs):
    """Application frames: A('com.acme.Foo.bar:12', ...)."""
    return F('\n'.join('APP ' + s for s in specs))


UNDERTOW = F("""
UTS io.undertow.servlet.handlers.ServletHandler.handleRequest:74
UTS io.undertow.servlet.handlers.security.ServletSecurityRoleHandler.handleRequest:62
UTS io.undertow.servlet.handlers.ServletChain$1.handleRequest:68
UTS io.undertow.servlet.handlers.ServletDispatchingHandler.handleRequest:36
WFUT org.wildfly.extension.undertow.security.SecurityContextAssociationHandler.handleRequest:78
UT io.undertow.server.handlers.PredicateHandler.handleRequest:43
UTS io.undertow.servlet.handlers.RedirectDirHandler.handleRequest:68
UTS io.undertow.servlet.handlers.security.SSLInformationAssociationHandler.handleRequest:117
UTS io.undertow.servlet.handlers.security.ServletAuthenticationCallHandler.handleRequest:57
UT io.undertow.server.handlers.PredicateHandler.handleRequest:43
UT io.undertow.security.handlers.AbstractConfidentialityHandler.handleRequest:46
UTS io.undertow.servlet.handlers.security.ServletConfidentialityConstraintHandler.handleRequest:64
UT io.undertow.security.handlers.AuthenticationMechanismsHandler.handleRequest:60
UTS io.undertow.servlet.handlers.security.CachedAuthenticatedSessionHandler.handleRequest:77
UT io.undertow.security.handlers.AbstractSecurityContextAssociationHandler.handleRequest:43
WFUT org.wildfly.extension.undertow.deployment.GlobalRequestControllerHandler.handleRequest:68
UTS io.undertow.servlet.handlers.SendErrorPageHandler.handleRequest:52
UTS io.undertow.servlet.handlers.ServletInitialHandler.handleFirstRequest:276
UTS io.undertow.servlet.handlers.ServletInitialHandler$1.call:135
UTS io.undertow.servlet.handlers.ServletInitialHandler$1.call:132
UTS io.undertow.servlet.core.ServletRequestContextThreadSetupAction$1.call:48
UTS io.undertow.servlet.core.ContextClassLoaderSetupAction$1.call:43
WFUT org.wildfly.extension.undertow.deployment.UndertowDeploymentInfoService$UndertowThreadSetupAction.lambda$create$0:1556
UTS io.undertow.servlet.handlers.ServletInitialHandler.dispatchRequest:256
UTS io.undertow.servlet.handlers.ServletInitialHandler.handleRequest:101
UT io.undertow.server.Connectors.executeRootHandler:393
UT io.undertow.server.HttpServerExchange$1.run:859
THR org.jboss.threads.ContextHandleRunnable.run:66
THR org.jboss.threads.EnhancedQueueExecutor$Task.doRunWith:1990
THR org.jboss.threads.EnhancedQueueExecutor$Task.run:1974
THR org.jboss.threads.EnhancedQueueExecutor$ThreadBody.doRunTask:1525
THR org.jboss.threads.EnhancedQueueExecutor$ThreadBody.run:1377
XNIO org.xnio.XnioWorker$WorkerThreadFactory$1$1.run:1282
JB java.lang.Thread.run:1583
""")

SERVLET_RE = F("""
RE org.jboss.resteasy.plugins.server.servlet.ServletContainerDispatcher.service:249
RE org.jboss.resteasy.plugins.server.servlet.HttpServletDispatcher.service:60
RE org.jboss.resteasy.plugins.server.servlet.HttpServletDispatcher.service:55
SERV jakarta.servlet.http.HttpServlet.service:614
""")

RE_DISPATCH = F("""
RE org.jboss.resteasy.core.SynchronousDispatcher.lambda$invoke$4:261
RE org.jboss.resteasy.core.SynchronousDispatcher.lambda$preprocess$0:161
RE org.jboss.resteasy.core.interception.jaxrs.PreMatchContainerRequestContext.filter:364
RE org.jboss.resteasy.core.SynchronousDispatcher.preprocess:164
RE org.jboss.resteasy.core.SynchronousDispatcher.invoke:247
""")

RE_INVOKE = F("""
JB jdk.internal.reflect.DirectMethodHandleAccessor.invoke:103
JB java.lang.reflect.Method.invoke:580
RE org.jboss.resteasy.core.MethodInjectorImpl.invoke:170
RE org.jboss.resteasy.core.MethodInjectorImpl.lambda$invoke$3:130
JB java.util.concurrent.CompletableFuture.uniApplyNow:684
JB java.util.concurrent.CompletableFuture.uniApplyStage:662
JB java.util.concurrent.CompletableFuture.thenApply:2200
RE org.jboss.resteasy.core.MethodInjectorImpl.invoke:144
RE org.jboss.resteasy.core.ResourceMethodInvoker.internalInvokeOnTarget:662
RE org.jboss.resteasy.core.ResourceMethodInvoker.invokeOnTargetAfterFilter:524
RE org.jboss.resteasy.core.ResourceMethodInvoker.lambda$invokeOnTarget$2:474
RE org.jboss.resteasy.core.interception.jaxrs.PreMatchContainerRequestContext.filter:364
RE org.jboss.resteasy.core.ResourceMethodInvoker.invokeOnTarget:476
RE org.jboss.resteasy.core.ResourceMethodInvoker.invoke:434
RE org.jboss.resteasy.core.ResourceMethodInvoker.invoke:408
RE org.jboss.resteasy.core.ResourceMethodInvoker.invoke:69
RE org.jboss.resteasy.core.SynchronousDispatcher.invoke:492
""") + RE_DISPATCH

EJB_PRE_TX = F("""
JB jdk.internal.reflect.DirectMethodHandleAccessor.invoke:103
JB java.lang.reflect.Method.invoke:580
EE org.jboss.as.ee.component.ManagedReferenceMethodInterceptor.processInvocation:52
INV org.jboss.invocation.InterceptorContext.proceed:422
INV org.jboss.invocation.InterceptorContext$Invocation.proceed:509
WELD org.jboss.as.weld.interceptors.Jsr299BindingsInterceptor.delegateInterception:79
WELD org.jboss.as.weld.interceptors.Jsr299BindingsInterceptor.doMethodInterception:89
WELD org.jboss.as.weld.interceptors.Jsr299BindingsInterceptor.processInvocation:102
EE org.jboss.as.ee.component.interceptors.UserInterceptorFactory$1.processInvocation:63
INV org.jboss.invocation.InterceptorContext.proceed:422
EJB org.jboss.as.ejb3.component.invocationmetrics.ExecutionTimeInterceptor.processInvocation:43
INV org.jboss.invocation.InterceptorContext.proceed:422
JPA org.jboss.as.jpa.interceptor.SBInvocationInterceptor.processInvocation:47
INV org.jboss.invocation.InterceptorContext.proceed:422
EE org.jboss.as.ee.concurrent.ConcurrentContextInterceptor.processInvocation:45
INV org.jboss.invocation.InterceptorContext.proceed:422
INV org.jboss.invocation.InitialInterceptor.processInvocation:40
INV org.jboss.invocation.InterceptorContext.proceed:422
INV org.jboss.invocation.ChainedInterceptor.processInvocation:53
EE org.jboss.as.ee.component.interceptors.ComponentDispatcherInterceptor.processInvocation:52
INV org.jboss.invocation.InterceptorContext.proceed:422
EJB org.jboss.as.ejb3.component.pool.PooledInstanceInterceptor.processInvocation:60
INV org.jboss.invocation.InterceptorContext.proceed:422
""")

EJB_TX_DOWN = F("""
EJB org.jboss.as.ejb3.tx.CMTTxInterceptor.invokeInOurTx:229
EJB org.jboss.as.ejb3.tx.CMTTxInterceptor.required:420
EJB org.jboss.as.ejb3.tx.CMTTxInterceptor.processInvocation:153
INV org.jboss.invocation.InterceptorContext.proceed:422
INV org.jboss.invocation.InterceptorContext$Invocation.proceed:509
WELDE org.jboss.weld.module.ejb.AbstractEJBRequestScopeActivationInterceptor.aroundInvoke:81
WELD org.jboss.as.weld.ejb.EjbRequestScopeActivationInterceptor.processInvocation:89
INV org.jboss.invocation.InterceptorContext.proceed:422
EJB org.jboss.as.ejb3.component.interceptors.CurrentInvocationContextInterceptor.processInvocation:41
INV org.jboss.invocation.InterceptorContext.proceed:422
EJB org.jboss.as.ejb3.component.invocationmetrics.WaitTimeInterceptor.processInvocation:47
INV org.jboss.invocation.InterceptorContext.proceed:422
EJB org.jboss.as.ejb3.security.ElytronInterceptorFactory$ElytronInterceptor.processInvocation:72
INV org.jboss.invocation.InterceptorContext.proceed:422
EE org.jboss.as.ee.component.NamespaceContextInterceptor.processInvocation:50
INV org.jboss.invocation.InterceptorContext.proceed:422
EJB org.jboss.as.ejb3.component.interceptors.LoggingInterceptor.processInvocation:57
INV org.jboss.invocation.InterceptorContext.proceed:422
EE org.jboss.as.ee.component.TCCLInterceptor.processInvocation:45
INV org.jboss.invocation.InterceptorContext.proceed:422
INV org.jboss.invocation.ChainedInterceptor.processInvocation:61
EE org.jboss.as.ee.component.ViewService$View.invoke:195
EE org.jboss.as.ee.component.ViewDescription$1.processInvocation:182
INV org.jboss.invocation.InterceptorContext.proceed:422
INV org.jboss.invocation.ChainedInterceptor.processInvocation:61
EE org.jboss.as.ee.component.ProxyInvocationHandler.invoke:81
""")

EJB_EXC_TOP = F("""
EJB org.jboss.as.ejb3.tx.CMTTxInterceptor.handleExceptionInOurTx:174
EJB org.jboss.as.ejb3.tx.CMTTxInterceptor.invokeInOurTx:243
""")

HIB_CONVERT = F("""
HIB org.hibernate.exception.internal.SQLStateConversionDelegate.convert:95
HIB org.hibernate.exception.internal.StandardSQLExceptionConverter.convert:58
HIB org.hibernate.engine.jdbc.spi.SqlExceptionHelper.convert:108
HIB org.hibernate.engine.jdbc.spi.SqlExceptionHelper.convert:94
""")

HIB_RSRI_UPD_EXC = F("HIB org.hibernate.engine.jdbc.internal.ResultSetReturnImpl.executeUpdate:211")
HIB_RSRI_UPD = F("HIB org.hibernate.engine.jdbc.internal.ResultSetReturnImpl.executeUpdate:194")

HIB_INSERT_BELOW = F("""
HIB org.hibernate.engine.jdbc.mutation.internal.AbstractMutationExecutor.performNonBatchedMutation:108
HIB org.hibernate.engine.jdbc.mutation.internal.MutationExecutorSingleNonBatched.performNonBatchedOperations:40
HIB org.hibernate.engine.jdbc.mutation.internal.AbstractMutationExecutor.execute:52
HIB org.hibernate.persister.entity.mutation.InsertCoordinator.doStaticInserts:171
HIB org.hibernate.persister.entity.mutation.InsertCoordinator.coordinateInsert:112
HIB org.hibernate.persister.entity.AbstractEntityPersister.insert:2860
HIB org.hibernate.action.internal.EntityInsertAction.execute:81
HIB org.hibernate.engine.spi.ActionQueue.executeActions:671
HIB org.hibernate.engine.spi.ActionQueue.executeActions:518
HIB org.hibernate.event.internal.AbstractFlushingEventListener.performExecutions:380
HIB org.hibernate.event.internal.DefaultFlushEventListener.onFlush:39
HIB org.hibernate.event.service.internal.EventListenerGroupImpl.fireEventOnEachListener:127
HIB org.hibernate.internal.SessionImpl.doFlush:1412
HIB org.hibernate.internal.SessionImpl.flush:1398
JPA org.jboss.as.jpa.container.AbstractEntityManager.flush:451
""")

HIB_UPDATE_BELOW = F("""
HIB org.hibernate.engine.jdbc.mutation.internal.AbstractMutationExecutor.performNonBatchedMutation:108
HIB org.hibernate.engine.jdbc.mutation.internal.MutationExecutorSingleNonBatched.performNonBatchedOperations:40
HIB org.hibernate.engine.jdbc.mutation.internal.AbstractMutationExecutor.execute:52
HIB org.hibernate.persister.entity.mutation.UpdateCoordinatorStandard.doVersionUpdate:833
HIB org.hibernate.persister.entity.mutation.UpdateCoordinatorStandard.coordinateUpdate:216
HIB org.hibernate.persister.entity.AbstractEntityPersister.update:2913
HIB org.hibernate.action.internal.EntityUpdateAction.execute:168
HIB org.hibernate.engine.spi.ActionQueue.executeActions:671
HIB org.hibernate.engine.spi.ActionQueue.executeActions:518
HIB org.hibernate.event.internal.AbstractFlushingEventListener.performExecutions:380
HIB org.hibernate.event.internal.DefaultFlushEventListener.onFlush:39
HIB org.hibernate.event.service.internal.EventListenerGroupImpl.fireEventOnEachListener:127
HIB org.hibernate.internal.SessionImpl.doFlush:1412
HIB org.hibernate.internal.SessionImpl.flush:1398
JPA org.jboss.as.jpa.container.AbstractEntityManager.flush:451
""")

PG_UPDATE = F("""
PG org.postgresql.core.v3.QueryExecutorImpl.receiveErrorResponse:2725
PG org.postgresql.core.v3.QueryExecutorImpl.processResults:2412
PG org.postgresql.core.v3.QueryExecutorImpl.execute:371
PG org.postgresql.jdbc.PgStatement.executeInternal:502
PG org.postgresql.jdbc.PgStatement.execute:419
PG org.postgresql.jdbc.PgPreparedStatement.executeWithFlags:194
PG org.postgresql.jdbc.PgPreparedStatement.executeUpdate:155
IJA org.jboss.jca.adapters.jdbc.WrappedPreparedStatement.executeUpdate:537
""")

HIB_QUERY = F("""
HIB org.hibernate.engine.jdbc.internal.StatementPreparerImpl$StatementPreparationTemplate.prepareStatement:177
HIB org.hibernate.engine.jdbc.internal.StatementPreparerImpl.prepareQueryStatement:151
HIB org.hibernate.sql.results.jdbc.internal.DeferredResultSetAccess.executeQuery:212
HIB org.hibernate.sql.results.jdbc.internal.DeferredResultSetAccess.getResultSet:163
HIB org.hibernate.sql.results.jdbc.internal.JdbcValuesResultSetImpl.advanceNext:254
HIB org.hibernate.sql.results.jdbc.internal.JdbcValuesResultSetImpl.processNext:134
HIB org.hibernate.sql.results.jdbc.internal.AbstractJdbcValues.next:19
HIB org.hibernate.sql.results.internal.RowProcessingStateStandardImpl.next:66
HIB org.hibernate.sql.results.spi.ListResultsConsumer.consume:202
HIB org.hibernate.sql.exec.internal.JdbcSelectExecutorStandardImpl.doExecuteQuery:361
HIB org.hibernate.sql.exec.internal.JdbcSelectExecutorStandardImpl.executeQuery:168
HIB org.hibernate.sql.exec.internal.JdbcSelectExecutorStandardImpl.list:93
HIB org.hibernate.query.sqm.internal.ConcreteSqmSelectQueryPlan.lambda$new$0:110
HIB org.hibernate.query.sqm.internal.ConcreteSqmSelectQueryPlan.withCacheableSqmInterpretation:303
HIB org.hibernate.query.sqm.internal.ConcreteSqmSelectQueryPlan.performList:244
HIB org.hibernate.query.sqm.internal.QuerySqmImpl.doList:518
HIB org.hibernate.query.spi.AbstractSelectionQuery.list:367
HIB org.hibernate.query.Query.getResultList:119
""")

HIB_CONN_EXC = HIB_CONVERT[:1] + HIB_CONVERT[1:] + F("""
HIB org.hibernate.resource.jdbc.internal.LogicalConnectionManagedImpl.acquireConnectionIfNeeded:116
HIB org.hibernate.resource.jdbc.internal.LogicalConnectionManagedImpl.getPhysicalConnection:143
""")
DS_GET = F("""
ASC org.jboss.as.connector.subsystems.datasources.WildFlyDataSource.getConnection:64
HIB org.hibernate.engine.jdbc.connections.internal.DatasourceConnectionProviderImpl.getConnection:122
HIB org.hibernate.internal.NonContextualJdbcConnectionAccess.obtainConnection:46
HIB org.hibernate.resource.jdbc.internal.LogicalConnectionManagedImpl.acquireConnectionIfNeeded:113
HIB org.hibernate.resource.jdbc.internal.LogicalConnectionManagedImpl.getPhysicalConnection:143
""")
IJ_SQLEXC_TOP = F("IJA org.jboss.jca.adapters.jdbc.WrapperDataSource.getConnection:159")
IJ_453_TOP = F("""
IJ org.jboss.jca.core.connectionmanager.AbstractConnectionManager.getManagedConnection:690
IJ org.jboss.jca.core.connectionmanager.tx.TxConnectionManagerImpl.getManagedConnection:430
IJ org.jboss.jca.core.connectionmanager.AbstractConnectionManager.allocateConnection:789
IJA org.jboss.jca.adapters.jdbc.WrapperDataSource.getConnection:151
""")
IJ_655_TOP = F("""
IJ org.jboss.jca.core.connectionmanager.pool.mcp.SemaphoreConcurrentLinkedDequeManagedConnectionPool.getConnection:570
IJ org.jboss.jca.core.connectionmanager.pool.AbstractPool.getSimpleConnection:632
IJ org.jboss.jca.core.connectionmanager.pool.AbstractPool.getConnection:604
IJ org.jboss.jca.core.connectionmanager.AbstractConnectionManager.getManagedConnection:624
""")

THREADPOOL_BOTTOM = F("""
JB java.util.concurrent.ThreadPoolExecutor.runWorker:1144
JB java.util.concurrent.ThreadPoolExecutor$Worker.run:642
JB java.lang.Thread.run:1583
""")

SOCKET_READ = F("""
JB sun.nio.ch.NioSocketImpl.timedRead:278
JB sun.nio.ch.NioSocketImpl.implRead:304
JB sun.nio.ch.NioSocketImpl.read:346
JB sun.nio.ch.NioSocketImpl$1.read:796
JB java.net.Socket$SocketInputStream.read:1099
JB sun.security.ssl.SSLSocketInputRecord.read:489
JB sun.security.ssl.SSLSocketInputRecord.readHeader:483
JB sun.security.ssl.SSLSocketInputRecord.bytesInCompletePacket:70
JB sun.security.ssl.SSLSocketImpl.readApplicationRecord:1461
JB sun.security.ssl.SSLSocketImpl$AppInputStream.read:1066
HC org.apache.http.impl.io.SessionInputBufferImpl.streamRead:137
HC org.apache.http.impl.io.SessionInputBufferImpl.fillBuffer:153
HC org.apache.http.impl.io.SessionInputBufferImpl.readLine:280
HC org.apache.http.impl.conn.DefaultHttpResponseParser.parseHead:138
HC org.apache.http.impl.conn.DefaultHttpResponseParser.parseHead:56
HC org.apache.http.impl.io.AbstractMessageParser.parse:259
HC org.apache.http.impl.DefaultBHttpClientConnection.receiveResponseHeader:163
HC org.apache.http.impl.conn.CPoolProxy.receiveResponseHeader:157
HC org.apache.http.protocol.HttpRequestExecutor.doReceiveResponse:273
HC org.apache.http.protocol.HttpRequestExecutor.execute:125
HC org.apache.http.impl.execchain.MainClientExec.execute:272
HC org.apache.http.impl.execchain.ProtocolExec.execute:186
HC org.apache.http.impl.execchain.RetryExec.execute:89
HC org.apache.http.impl.execchain.RedirectExec.execute:110
HC org.apache.http.impl.client.InternalHttpClient.doExecute:185
HC org.apache.http.impl.client.CloseableHttpClient.execute:83
HC org.apache.http.impl.client.CloseableHttpClient.execute:56
REC org.jboss.resteasy.client.jaxrs.engines.ManualClosingApacheHttpClient43Engine.invoke:280
""")
CLIENT_CALL = F("""
REC org.jboss.resteasy.client.jaxrs.internal.ClientInvocation.invoke:494
REC org.jboss.resteasy.client.jaxrs.internal.ClientInvocation.invoke:68
REC org.jboss.resteasy.client.jaxrs.internal.ClientInvocationBuilder.post:213
""") + A('com.acme.shop.payment.PaymentGatewayClient.authorize:94',
         'com.acme.shop.payment.PaymentGatewayClient.lambda$authorizeAsync$0:71') + F("""
JB java.util.concurrent.CompletableFuture$AsyncSupply.run:1768
""") + THREADPOOL_BOTTOM
CLIENT_EXC_TOP = F("REC org.jboss.resteasy.client.jaxrs.engines.ManualClosingApacheHttpClient43Engine.invoke:302")


def _wf(f):
    return '\tat %s%s(%s)' % f


def _l4j(f):
    return '\tat %s(%s) ~[?:?]' % (f[1], f[2])


def _skel(chain, rf):
    out = ['%s']
    out.extend(rf(f) for f in chain[0])
    for i in range(1, len(chain)):
        enc, cur = chain[i - 1], chain[i]
        m, n = len(cur) - 1, len(enc) - 1
        while m >= 0 and n >= 0 and cur[m] == enc[n]:
            m -= 1
            n -= 1
        out.append('Caused by: %s')
        out.extend(rf(f) for f in cur[:m + 1])
        common = len(cur) - 1 - m
        if common:
            out.append('\t... %d more' % common)
    return '\n'.join(out) + '\n'


class Trace:
    """Pre-rendered exception chain; headers (exception class + message) are filled in later."""
    __slots__ = ('wf', 'l4j', 'frames')

    def __init__(self, *chain):
        self.wf = _skel(chain, _wf)
        self.l4j = _skel(chain, _l4j)
        self.frames = sum(len(c) for c in chain)

    def text(self, style, *headers):
        return (self.wf if style == 'wf' else self.l4j) % headers


def rec(style, level, logger, thread, msg, exc=None):
    """One log record without the timestamp (the timestamp is prepended when writing)."""
    if style == 'wf':
        if exc:
            return ' %s [%s] (%s) %s: %s' % (LVL[level], logger, thread, msg, exc)
        return ' %s [%s] (%s) %s\n' % (LVL[level], logger, thread, msg)
    s = ' [%s] %s %s - %s\n' % (thread, LVL[level], logger, msg)
    return s + exc if exc else s


# --------------------------------------------------------------------------------------
# application call scenarios (REST resource -> EJB -> repository)
# --------------------------------------------------------------------------------------
class Scn:
    def __init__(self, comp, view_no, res, svc, sig, path, repo, qrepo):
        self.comp = comp
        self.res = A(res)
        self.svc = A(*svc) if isinstance(svc, tuple) else A(svc)
        cls = svc[-1] if isinstance(svc, tuple) else svc
        meth = cls.rsplit(':', 1)[0]
        self.view = A('%s$$$view%d.%s:U' % (meth.rsplit('.', 1)[0], view_no, meth.rsplit('.', 1)[1]))
        self.sig = sig
        self.path = path
        self.repo = A(repo) if repo else []
        self.qrepo = A(qrepo) if qrepo else []

    def rest_bottom(self):
        return self.res + RE_INVOKE + SERVLET_RE + UNDERTOW

    def tail(self):
        """Stack below the service code: EJB interceptors, proxy, REST resource, servlet, undertow."""
        return self.svc + EJB_PRE_TX + EJB_TX_DOWN + self.view + self.rest_bottom()

    def ejb_exc(self):
        return EJB_EXC_TOP + EJB_TX_DOWN[1:] + self.view + self.rest_bottom()


SCN = {
    'order': Scn('OrderService', 12, 'com.acme.shop.api.OrderResource.create:57',
                 'com.acme.shop.OrderService.place:88',
                 'public com.acme.shop.model.Order com.acme.shop.OrderService.place(com.acme.shop.dto.OrderRequest)',
                 '/shop/api/orders', 'com.acme.shop.repo.OrderRepository.save:41',
                 'com.acme.shop.repo.CustomerRepository.findById:29'),
    'register': Scn('CustomerService', 3, 'com.acme.shop.api.CustomerResource.register:39',
                    'com.acme.shop.customer.CustomerService.register:52',
                    'public com.acme.shop.model.Customer com.acme.shop.customer.CustomerService.register(com.acme.shop.dto.RegistrationRequest)',
                    '/shop/api/customers', 'com.acme.shop.repo.CustomerRepository.persist:33',
                    'com.acme.shop.repo.CustomerRepository.findByEmail:45'),
    'catalog': Scn('CatalogService', 5, 'com.acme.shop.api.ProductResource.byCategory:73',
                   'com.acme.shop.catalog.CatalogService.findByCategory:35',
                   'public java.util.List com.acme.shop.catalog.CatalogService.findByCategory(long,int,int)',
                   '/shop/api/products', None, 'com.acme.shop.repo.ProductRepository.findByCategory:57'),
    'cart': Scn('CartService', 7, 'com.acme.shop.api.CartResource.addItem:44',
                'com.acme.shop.cart.CartService.addItem:61',
                'public void com.acme.shop.cart.CartService.addItem(java.lang.String,long,int)',
                '/shop/api/cart', 'com.acme.shop.repo.CartRepository.save:38',
                'com.acme.shop.repo.CartRepository.findById:24'),
    'checkout': Scn('CheckoutService', 9, 'com.acme.shop.api.CheckoutResource.quote:48',
                    ('com.acme.shop.checkout.ShippingCalculator.calculate:61',
                     'com.acme.shop.checkout.CheckoutService.quote:77'),
                    'public com.acme.shop.checkout.Quote com.acme.shop.checkout.CheckoutService.quote(java.lang.String)',
                    '/shop/api/checkout', None, 'com.acme.shop.repo.CartRepository.findById:24'),
    'reserve': Scn('InventoryService', 4, 'com.acme.shop.api.OrderResource.confirm:83',
                   'com.acme.shop.inventory.InventoryService.reserve:66',
                   'public void com.acme.shop.inventory.InventoryService.reserve(java.lang.String,java.util.List)',
                   '/shop/api/orders', 'com.acme.shop.repo.InventoryRepository.decrement:48', None),
    'report': Scn('ReportService', 2, 'com.acme.shop.api.ReportResource.monthly:31',
                  'com.acme.shop.report.ReportService.monthlySales:52',
                  'public com.acme.shop.report.SalesReport com.acme.shop.report.ReportService.monthlySales(java.time.YearMonth)',
                  '/shop/api/reports/monthly', None, 'com.acme.shop.repo.ReportRepository.monthlySales:77'),
}


def build_traces():
    T = {}
    # duplicate key on insert: EJBException -> ConstraintViolationException -> PSQLException
    T['dup'] = {}
    for k in ('order', 'register', 'cart'):
        s = SCN[k]
        low = HIB_INSERT_BELOW + s.repo + s.tail()
        T['dup'][k] = Trace(s.ejb_exc(), HIB_CONVERT + HIB_RSRI_UPD_EXC + low,
                            PG_UPDATE + HIB_RSRI_UPD + low)
    # deadlock on update
    s = SCN['reserve']
    low = HIB_UPDATE_BELOW + s.repo + s.tail()
    T['deadlock'] = Trace(s.ejb_exc(), HIB_CONVERT + HIB_RSRI_UPD_EXC + low, PG_UPDATE + HIB_RSRI_UPD + low)
    # pool exhaustion: EJBException -> JDBCConnectionException -> SQLException -> RE IJ000453 -> RE IJ000655
    T['ij'] = {}
    for k in ('order', 'catalog', 'cart', 'checkout'):
        s = SCN[k]
        low = HIB_QUERY + s.qrepo + s.tail()
        sqlexc = IJ_SQLEXC_TOP + DS_GET + low
        r453 = IJ_453_TOP + DS_GET + low
        r655 = IJ_655_TOP + IJ_453_TOP[1:] + DS_GET + low
        T['ij'][k] = Trace(s.ejb_exc(), HIB_CONN_EXC + low, sqlexc, r453, r655)
    # NPE in ShippingCalculator
    s = SCN['checkout']
    T['npe'] = Trace(s.ejb_exc(), s.tail())
    # hang aftermath: tx rolled back / pool permits
    T['rollback'] = {}
    for k in ('order', 'cart', 'checkout'):
        s = SCN[k]
        outer = F("""
EJB org.jboss.as.ejb3.tx.CMTTxInterceptor.handleEndTransactionException:150
EJB org.jboss.as.ejb3.tx.CMTTxInterceptor.endTransaction:127
EJB org.jboss.as.ejb3.tx.CMTTxInterceptor.invokeInOurTx:257
""") + EJB_TX_DOWN[1:] + s.view + s.rest_bottom()
        cause = F("""
TXN com.arjuna.ats.internal.jta.transaction.arjunacore.TransactionImple.commitAndDisassociate:1302
TXN com.arjuna.ats.internal.jta.transaction.arjunacore.BaseTransaction.commit:104
TXN com.arjuna.ats.jbossatx.BaseTransactionManagerDelegate.commit:75
WFTC org.wildfly.transaction.client.LocalTransaction.commitAndDissociate:78
WFTC org.wildfly.transaction.client.ContextTransactionManager.commit:73
EJB org.jboss.as.ejb3.tx.CMTTxInterceptor.endTransaction:94
EJB org.jboss.as.ejb3.tx.CMTTxInterceptor.invokeInOurTx:257
""") + EJB_TX_DOWN[1:] + s.view + s.rest_bottom()
        T['rollback'][k] = Trace(outer, cause)
    T['permit'] = {}
    for k in ('order', 'catalog', 'cart'):
        s = SCN[k]
        T['permit'][k] = Trace(F("""
EJB org.jboss.as.ejb3.pool.strictmax.StrictMaxPool.get:122
EJB org.jboss.as.ejb3.component.pool.PooledInstanceInterceptor.processInvocation:47
INV org.jboss.invocation.InterceptorContext.proceed:422
""") + EJB_TX_DOWN + s.view + s.rest_bottom())
    T['reject'] = Trace(F("""
THR org.jboss.threads.EnhancedQueueExecutor.rejectQueueFull:2179
THR org.jboss.threads.EnhancedQueueExecutor.execute:807
XNIO org.xnio.XnioWorker.execute:778
UT io.undertow.server.HttpServerExchange.dispatch:906
UT io.undertow.server.Connectors.executeRootHandler:393
UT io.undertow.server.protocol.http.HttpReadListener.handleEventWithNoRunningRequest:265
UT io.undertow.server.protocol.http.HttpReadListener.handleEvent:136
UT io.undertow.server.protocol.http.HttpReadListener.handleEvent:59
XNIO org.xnio.ChannelListeners.invokeChannelListener:92
XNIO org.xnio.conduits.ReadReadyHandler$ChannelListenerHandler.readReady:66
XNION org.xnio.nio.NioSocketConduit.handleReady:89
XNION org.xnio.nio.WorkerThread.run:624
"""))
    # payment gateway timeout: ProcessingException -> SocketTimeoutException
    T['pay'] = Trace(CLIENT_EXC_TOP + CLIENT_CALL, SOCKET_READ + CLIENT_CALL)
    # StackOverflowError (cause trace cut at 1024 frames, as the JVM does)
    outer = F("""
RE org.jboss.resteasy.core.ExceptionHandler.handleApplicationException:76
RE org.jboss.resteasy.core.ExceptionHandler.handleException:227
RE org.jboss.resteasy.core.SynchronousDispatcher.writeException:224
RE org.jboss.resteasy.core.SynchronousDispatcher.invoke:500
""") + RE_DISPATCH + SERVLET_RE + UNDERTOW
    rep = A('com.acme.shop.catalog.CategoryTreeBuilder.addChildren:48',
            'com.acme.shop.catalog.CategoryTreeBuilder.lambda$addChildren$0:52') + F(
        'JB java.util.ArrayList.forEach:1596')
    soe = F("JB java.util.HashMap.hash:338\nJB java.util.HashMap.get:556") + A(
        'com.acme.shop.catalog.CategoryCache.children:41')
    while len(soe) < 1024:
        soe.extend(rep)
    T['soe'] = Trace(outer, soe[:1024])
    # OutOfMemoryError variants
    T['oom_ut'] = Trace(F("""
JB java.util.Arrays.copyOf:3537
JB java.lang.AbstractStringBuilder.ensureCapacityInternal:228
JB java.lang.AbstractStringBuilder.append:582
JB java.lang.StringBuilder.append:179
""") + A('com.acme.shop.export.CsvExporter.appendRow:112', 'com.acme.shop.export.CsvExporter.export:67',
         'com.acme.shop.api.ExportResource.exportOrders:39') + RE_INVOKE + SERVLET_RE + UNDERTOW)
    s = SCN['report']
    T['oom_ejb'] = Trace(s.ejb_exc(), F("""
JB java.util.Arrays.copyOf:3512
JB java.util.ArrayList.grow:237
JB java.util.ArrayList.grow:244
JB java.util.ArrayList.add:483
JB java.util.ArrayList.add:496
""") + HIB_QUERY[8:] + s.qrepo + s.tail())
    T['oom_timer'] = F("""
JB java.util.Arrays.copyOf:3537
JB java.lang.AbstractStringBuilder.ensureCapacityInternal:228
JB java.lang.AbstractStringBuilder.append:582
JB java.lang.StringBuilder.append:179
""") + A('com.acme.shop.legacy.ExchangeRateUpdater.parse:133', 'com.acme.shop.legacy.ExchangeRateUpdater.run:58') + F("""
JB java.util.TimerThread.mainLoop:566
JB java.util.TimerThread.run:516
""")
    # background noise
    T['notfound'] = Trace(F("""
RE org.jboss.resteasy.core.registry.SegmentNode.match:117
RE org.jboss.resteasy.core.registry.RootNode.match:43
RE org.jboss.resteasy.core.registry.RootClassNode.match:47
RE org.jboss.resteasy.core.ResourceMethodRegistry.getResourceInvoker:566
RE org.jboss.resteasy.core.SynchronousDispatcher.getInvoker:173
RE org.jboss.resteasy.core.SynchronousDispatcher.lambda$invoke$4:255
""") + RE_DISPATCH[1:] + SERVLET_RE + UNDERTOW)
    T['toobig'] = Trace(F("""
UT io.undertow.conduits.FixedLengthStreamSourceConduit.checkMaxSize:168
UT io.undertow.conduits.FixedLengthStreamSourceConduit.read:229
XNIO org.xnio.conduits.ConduitStreamSourceChannel.read:127
UT io.undertow.channels.DetachableStreamSourceChannel.read:209
UT io.undertow.server.HttpServerExchange$ReadDispatchChannel.read:2470
XNIO org.xnio.channels.Channels.readBlocking:295
UTS io.undertow.servlet.spec.ServletInputStreamImpl.readIntoBuffer:192
UTS io.undertow.servlet.spec.ServletInputStreamImpl.read:168
JB java.io.InputStream.transferTo:796
""") + A('com.acme.shop.media.ImageStore.store:58', 'com.acme.shop.api.UploadResource.upload:52') + RE_INVOKE + SERVLET_RE + UNDERTOW)
    T['pipe'] = Trace(F("""
JB sun.nio.ch.SocketDispatcher.write0:N
JB sun.nio.ch.SocketDispatcher.write:62
JB sun.nio.ch.IOUtil.writeFromNativeBuffer:137
JB sun.nio.ch.IOUtil.write:102
JB sun.nio.ch.IOUtil.write:58
JB sun.nio.ch.SocketChannelImpl.write:542
XNION org.xnio.nio.NioSocketConduit.write:164
UT io.undertow.server.protocol.http.HttpResponseConduit.write:657
UT io.undertow.conduits.ChunkedStreamSinkConduit.write:131
XNIO org.xnio.conduits.ConduitStreamSinkChannel.write:150
UT io.undertow.channels.DetachableStreamSinkChannel.write:240
UT io.undertow.server.HttpServerExchange$WriteDispatchChannel.write:2154
UTS io.undertow.servlet.spec.ServletOutputStreamImpl.writeBufferBlocking:621
UTS io.undertow.servlet.spec.ServletOutputStreamImpl.write:145
RE org.jboss.resteasy.util.CommitHeaderOutputStream.write:67
""") + A('com.acme.shop.export.CsvExporter.writeRow:88', 'com.acme.shop.api.ExportResource.lambda$exportOrders$0:41') + F("""
RE org.jboss.resteasy.plugins.providers.StreamingOutputProvider.writeTo:46
RE org.jboss.resteasy.core.interception.jaxrs.AbstractWriterInterceptorContext.writeTo:241
RE org.jboss.resteasy.core.ServerResponseWriter.lambda$writeNomapResponse$3:189
RE org.jboss.resteasy.core.ServerResponseWriter.writeNomapResponse:213
RE org.jboss.resteasy.core.SynchronousDispatcher.writeResponse:660
RE org.jboss.resteasy.core.SynchronousDispatcher.invoke:493
""") + RE_DISPATCH + SERVLET_RE + UNDERTOW)
    T['ispn'] = Trace(F("""
ISPN org.infinispan.util.concurrent.locks.impl.DefaultLockManager$KeyAwareExtendedLockPromise.get:343
ISPN org.infinispan.util.concurrent.locks.impl.DefaultLockManager$KeyAwareExtendedLockPromise.lock:316
ISPN org.infinispan.interceptors.locking.PessimisticLockingInterceptor.visitDataWriteCommand:112
ISPN org.infinispan.interceptors.locking.AbstractLockingInterceptor.visitPutKeyValueCommand:84
ISPN org.infinispan.commands.write.PutKeyValueCommand.acceptVisitor:62
ISPN org.infinispan.interceptors.BaseAsyncInterceptor.invokeNextThenAccept:105
ISPN org.infinispan.interceptors.impl.TxInterceptor.handleWriteCommand:476
ISPN org.infinispan.interceptors.impl.TxInterceptor.visitPutKeyValueCommand:268
ISPN org.infinispan.interceptors.impl.InvocationContextInterceptor.visitCommand:65
ISPN org.infinispan.interceptors.impl.AsyncInterceptorChainImpl.invoke:239
ISPN org.infinispan.cache.impl.InvocationHelper.doInvoke:308
ISPN org.infinispan.cache.impl.InvocationHelper.invoke:102
ISPN org.infinispan.cache.impl.CacheImpl.put:1308
ISPN org.infinispan.cache.impl.AbstractDelegatingCache.put:449
CLU org.wildfly.clustering.web.infinispan.session.InfinispanSessionMetaDataFactory.createValue:102
CLU org.wildfly.clustering.web.infinispan.session.CompositeSessionFactory.createValue:57
CLU org.wildfly.clustering.web.infinispan.session.InfinispanSessionManager.createSession:206
UTS io.undertow.servlet.spec.HttpServletRequestImpl.getSession:465
""") + A('com.acme.shop.auth.SessionHelper.current:28') + SCN['cart'].rest_bottom())
    T['iae'] = Trace(A('com.acme.shop.repo.SortSpec.parse:34', 'com.acme.shop.api.ProductResource.search:96')
                     + RE_INVOKE + SERVLET_RE + UNDERTOW)
    mail_bottom = A('com.acme.shop.mail.MailService.sendOrderConfirmation:64',
                    'com.acme.shop.mail.MailService.lambda$sendAsync$0:41') + THREADPOOL_BOTTOM
    mail_top = F("""
MAIL org.eclipse.angus.mail.smtp.SMTPTransport.openServer:2258
MAIL org.eclipse.angus.mail.smtp.SMTPTransport.protocolConnect:753
MAIL jakarta.mail.Service.connect:342
MAIL jakarta.mail.Service.connect:222
MAIL jakarta.mail.Service.connect:171
MAIL jakarta.mail.Transport.send0:230
MAIL jakarta.mail.Transport.send:100
""")
    T['mail'] = Trace(mail_top + mail_bottom, F("""
JB sun.nio.ch.Net.pollConnect:N
JB sun.nio.ch.Net.pollConnectNow:682
JB sun.nio.ch.NioSocketImpl.timedFinishConnect:542
JB sun.nio.ch.NioSocketImpl.connect:592
JB java.net.SocksSocketImpl.connect:327
JB java.net.Socket.connect:751
JB java.net.Socket.connect:686
MAIL org.eclipse.angus.mail.util.SocketFetcher.createSocket:362
MAIL org.eclipse.angus.mail.util.SocketFetcher.getSocket:243
MAIL org.eclipse.angus.mail.smtp.SMTPTransport.openServer:2224
""") + mail_top[1:] + mail_bottom)
    return T


TR = build_traces()

# ======================================================================================
# random value helpers
# ======================================================================================
_FIRST = ('anna ben clara david emma felix greta hannah jonas julia lena lukas marie max mia noah paul '
          'sophie tim tom lea leon nina oskar jan eva karl ida olga peter sara finn emil rosa hugo').split()
_LAST = ('mueller schmidt schneider fischer weber meyer wagner becker schulz hoffmann koch richter klein '
         'wolf neumann schwarz braun zimmermann krueger hartmann lange werner krause lehmann koehler maier '
         'huber kaiser fuchs peters jung keller berger vogel').split()
_B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
_ADJ = 'Classic Smart Organic Compact Deluxe Ultra Eco Vintage Rugged Silent Mini Pro'.split()
_NOUN = ('Coffee Grinder|Desk Lamp|Water Bottle|Backpack|Headphones|Running Shoes|Yoga Mat|Kettle|'
         'Notebook|Phone Case|Toaster|Bike Light|Wool Socks|Chef Knife|Teapot|Keyboard').split('|')
_CATS = 'electronics kitchen sports office garden fashion toys books outdoor home'.split()
_SEARCH = ('coffee|lamp|bottle|bag|headphones|shoes|yoga|kettle|notebook|case|toaster|light|socks|knife|'
           'tea|keyboard|gift|xmas|sale|wireless').split('|')
_CARRIERS = ['DHL_PAKET', 'DPD_CLASSIC', 'UPS_STANDARD', 'HERMES', 'GLS']
_GEO = ['Berlin', 'Hamburg', 'Muenchen', 'Koeln', 'Frankfurt', 'Stuttgart', 'Leipzig', 'Dresden', 'Wien', 'Zuerich']


class Vals:
    def __init__(self, r):
        self.r = r
        self.users = sorted({'%s.%s' % (r.choice(_FIRST), r.choice(_LAST)) if r.random() < 0.6 else
                             '%s%s%d' % (r.choice(_FIRST), r.choice(_LAST)[:3], r.randint(1, 99))
                             for _ in range(3000)})
        self.products = ['%s %s' % (r.choice(_ADJ), r.choice(_NOUN)) for _ in range(400)]

    def uuid(self):
        h = '%032x' % self.r.getrandbits(128)
        return '%s-%s-4%s-%s%s-%s' % (h[:8], h[8:12], h[13:16], '89ab'[int(h[16], 16) & 3], h[17:20], h[20:])

    def sess(self):
        return ''.join(self.r.choices(_B64, k=40))

    def ip(self):
        r = self.r
        if r.random() < 0.7:
            return '10.%d.%d.%d' % (r.randint(0, 3), r.randint(0, 255), r.randint(1, 254))
        return '%d.%d.%d.%d' % (r.choice((31, 46, 62, 77, 80, 84, 87, 91, 93, 178, 188, 212, 217)),
                                r.randint(0, 255), r.randint(0, 255), r.randint(1, 254))

    def user(self):
        return self.r.choice(self.users)

    def email(self):
        return '%s@%s' % (self.user(), self.r.choice(('example.com', 'mail.example.org', 'example.net')))

    def masked_email(self):
        e = self.email()
        return e[0] + '***' + e[e.index('@'):]

    def dur(self, med, sigma=0.6):
        return max(1, int(self.r.lognormvariate(math.log(med), sigma)))

    def price(self):
        return '%.2f' % (self.r.choice((4.99, 9.99, 12.5, 19.99, 24.9, 29.99, 49.0, 79.99, 129.0)) *
                         self.r.randint(1, 3))

    def sku(self):
        return 'SKU-%05d' % self.r.randint(10000, 99999)

    def pid(self):
        return self.r.randint(1000, 48000)

    def cid(self):
        return self.r.randint(1000, 250000)

    def hexid(self, n=8):
        return '%0*x' % (n, self.r.getrandbits(4 * n))


class Ctx:
    """Mutable generation context (time dependent values)."""

    def __init__(self, start_dt):
        self.start_dt = start_dt
        self.t = 0
        self.version = '2.14.0'
        self.build = 4711
        self.txn_pid = '-3c2b1d4e'
        self.txc = 0x1f00

    @property
    def order_base(self):
        return 1048576 + int(self.t * 0.37)

    def txid(self, r):
        self.txc += r.randint(1, 40)
        return '0:ffff0a00020f:%s:6571f0a2:%x' % (self.txn_pid, self.txc)

    def iso(self, r):
        d = self.start_dt + dt.timedelta(seconds=self.t + r.randint(0, 3599), milliseconds=r.randint(0, 999))
        return d.strftime('%Y-%m-%dT%H:%M:%S.') + '%03dZ' % (d.microsecond // 1000)


def t_req(r):
    return 'default task-%d' % (r.randint(1, 64) if r.random() < 0.25 else r.randint(1, 24))


def t_ejb(r):
    return 'EJB default - %d' % r.randint(1, 16)


def t_pool(r):
    return 'pool-3-thread-%d' % r.randint(1, 20)


def t_io(r):
    return 'default I/O-%d' % r.randint(1, 8)


def t_any(r):
    x = r.random()
    if x < 0.75:
        return t_req(r)
    if x < 0.88:
        return t_ejb(r)
    if x < 0.97:
        return t_pool(r)
    return 'scheduler-%d' % r.randint(1, 4)


# ======================================================================================
# background templates
# ======================================================================================
def build_templates(V):
    r = V.r

    def rest_path():
        x = r.random()
        if x < 0.30:
            return 'GET', '/shop/api/products/%d' % V.pid(), 200
        if x < 0.42:
            return 'GET', '/shop/api/products?category=%s&page=%d&size=24' % (r.choice(_CATS), r.randint(0, 9)), 200
        if x < 0.52:
            return 'GET', '/shop/api/search?q=%s&page=0' % r.choice(_SEARCH), 200
        if x < 0.62:
            return 'POST', '/shop/api/cart/%s/items' % V.uuid(), 201
        if x < 0.70:
            return 'GET', '/shop/api/cart/%s' % V.uuid(), 200
        if x < 0.76:
            return 'POST', '/shop/api/checkout/%s/quote' % V.uuid(), 200
        if x < 0.82:
            return 'POST', '/shop/api/orders', 201
        if x < 0.88:
            return 'GET', '/shop/api/orders/A-%d' % r.randint(1000000, 1100000), 200
        if x < 0.93:
            return 'GET', '/shop/api/customers/%d' % V.cid(), 200
        if x < 0.97:
            return 'POST', '/shop/api/auth/login', 200
        return 'GET', '/shop/api/health', 200

    def sql_record(st, c, kind):
        th = t_req(r)
        if kind == 'select':
            x = r.randint(0, 5)
            if x == 0:
                sql = ('select p1_0.id,p1_0.category_id,p1_0.description,p1_0.name,p1_0.price,p1_0.sku,'
                       'p1_0.stock,p1_0.version from product p1_0 where p1_0.id=?')
                bv = [('BIGINT', V.pid())]
            elif x == 1:
                sql = ('select p1_0.id,p1_0.name,p1_0.price,p1_0.sku from product p1_0 join category c1_0 '
                       'on c1_0.id=p1_0.category_id where c1_0.slug=? order by p1_0.name offset ? rows fetch first ? rows only')
                bv = [('VARCHAR', r.choice(_CATS)), ('INTEGER', 24 * r.randint(0, 9)), ('INTEGER', 24)]
            elif x == 2:
                sql = ('select c1_0.id,c1_0.created_at,c1_0.email,c1_0.first_name,c1_0.last_name,c1_0.status '
                       'from customer c1_0 where c1_0.email=?')
                bv = [('VARCHAR', V.email())]
            elif x == 3:
                sql = ('select o1_0.id,o1_0.created_at,o1_0.customer_id,o1_0.order_no,o1_0.status,o1_0.total '
                       'from orders o1_0 where o1_0.order_no=?')
                bv = [('VARCHAR', 'A-%d' % (c.order_base - r.randint(0, 5000)))]
            elif x == 4:
                sql = ('select i1_0.order_id,i1_0.id,i1_0.price,i1_0.product_id,i1_0.quantity '
                       'from order_item i1_0 where i1_0.order_id=?')
                bv = [('BIGINT', c.order_base - r.randint(0, 5000) - 1000000)]
            else:
                sql = 'select c1_0.id,c1_0.customer_id,c1_0.updated_at from cart c1_0 where c1_0.id=?'
                bv = [('UUID', V.uuid())]
        elif kind == 'insert':
            if r.random() < 0.5:
                sql = 'insert into orders (created_at,customer_id,order_no,status,total,id) values (?,?,?,?,?,?)'
                bv = [('TIMESTAMP_UTC', c.iso(r)), ('BIGINT', V.cid()), ('VARCHAR', 'A-%d' % c.order_base),
                      ('VARCHAR', 'NEW'), ('NUMERIC', V.price()), ('BIGINT', c.order_base - 1000000)]
            else:
                sql = 'insert into cart_item (cart_id,product_id,quantity,id) values (?,?,?,?)'
                bv = [('UUID', V.uuid()), ('BIGINT', V.pid()), ('INTEGER', r.randint(1, 4)),
                      ('BIGINT', r.randint(1000000, 9000000))]
        else:
            if r.random() < 0.6:
                sql = 'update product set stock=?,version=? where id=? and version=?'
                v = r.randint(1, 900)
                bv = [('INTEGER', r.randint(0, 300)), ('INTEGER', v + 1), ('BIGINT', V.pid()), ('INTEGER', v)]
            else:
                sql = 'update orders set status=?,updated_at=? where id=?'
                bv = [('VARCHAR', r.choice(('PAID', 'SHIPPED', 'CANCELLED', 'PAYMENT_PENDING'))),
                      ('TIMESTAMP_UTC', c.iso(r)), ('BIGINT', c.order_base - r.randint(0, 5000) - 1000000)]
        out = [rec(st, 'DEBUG', 'org.hibernate.SQL', th, sql)]
        for i, (typ, v) in enumerate(bv, 1):
            out.append(rec(st, 'TRACE', 'org.hibernate.orm.jdbc.bind', th,
                           'binding parameter (%d:%s) <- [%s]' % (i, typ, v)))
        return NUL.join(out)

    # ---------------- WildFly server.log ----------------
    def s_matched(st, c):
        m, p, _ = rest_path()
        return rec(st, 'DEBUG', 'io.undertow.request', t_io(r), 'Matched prefix path /shop for path %s' % p.split('?')[0])

    def s_pathinfo(st, c):
        m, p, _ = rest_path()
        return rec(st, 'DEBUG', 'org.jboss.resteasy.resteasy_jaxrs.i18n', t_req(r),
                   'RESTEASY002315: PathInfo: %s' % p[9:].split('?')[0])

    def s_access(st, c):
        m, p, code = rest_path()
        if r.random() < 0.03:
            code = r.choice((400, 401, 403, 404, 409))
        return rec(st, 'INFO', 'com.acme.shop.api.RequestLoggingFilter', t_req(r),
                   '%s %s -> %d (%d ms) user=%s ip=%s session=%s' % (m, p, code, V.dur(35), V.user(), V.ip(), V.sess()))

    def s_jca_get(st, c):
        n = r.randint(2, 34)
        return rec(st, 'DEBUG', 'org.jboss.jca.core.connectionmanager.pool.strategy.OnePool', t_req(r),
                   'ShopDS: getConnection(null, WrappedConnectionRequestInfo@%s[userName=shop]) [%d/50]' % (V.hexid(), n))

    def s_jca_ret(st, c):
        return rec(st, 'DEBUG', 'org.jboss.jca.core.connectionmanager.pool.strategy.OnePool', t_req(r),
                   'ShopDS: returnConnection(%s, false) [%d/50]' % (V.hexid(), r.randint(1, 33)))

    def s_arj_begin(st, c):
        return rec(st, 'DEBUG', 'com.arjuna.ats.arjuna', t_req(r), 'BasicAction::Begin() for action-id %s' % c.txid(r))

    def s_arj_end(st, c):
        return rec(st, 'DEBUG', 'com.arjuna.ats.arjuna', t_req(r),
                   'BasicAction::End() for action-id %s' % c.txid(r))

    def s_order(st, c):
        return rec(st, 'INFO', 'com.acme.shop.OrderService', t_req(r),
                   'Order A-%d placed by customer %d (%d items, total %s EUR, payment=%s)' % (
                       c.order_base - r.randint(0, 30), V.cid(), r.randint(1, 7), V.price(),
                       r.choice(('CARD', 'PAYPAL', 'INVOICE', 'KLARNA'))))

    def s_login(st, c):
        return rec(st, 'INFO', 'com.acme.shop.auth.LoginService', t_req(r),
                   'User %s logged in from %s (session %s)' % (V.user(), V.ip(), V.sess()))

    def s_cache(st, c):
        return rec(st, 'DEBUG', 'com.acme.shop.catalog.ProductCache', t_req(r),
                   'Cache %s for product %d (region=products, size=%d)' % (
                       'hit' if r.random() < 0.85 else 'miss', V.pid(), r.randint(9000, 12000)))

    def s_cart(st, c):
        return rec(st, 'INFO', 'com.acme.shop.cart.CartService', t_req(r),
                   'Added %d x %s (%s) to cart %s' % (r.randint(1, 3), V.sku(), r.choice(V.products), V.uuid()))

    def s_checkout(st, c):
        return rec(st, 'INFO', 'com.acme.shop.checkout.CheckoutService', t_req(r),
                   'Checkout started for cart %s, customer %d, carrier %s' % (V.uuid(), V.cid(), r.choice(_CARRIERS)))

    def s_payok(st, c):
        return rec(st, 'INFO', 'com.acme.shop.payment.PaymentGatewayClient', t_pool(r),
                   'Payment authorized for order A-%d: txn=pay_%s, amount %s EUR in %d ms' % (
                       c.order_base - r.randint(0, 30), V.hexid(16), V.price(), V.dur(280, 0.4)))

    def s_mail(st, c):
        return rec(st, 'INFO', 'com.acme.shop.mail.MailService', t_pool(r),
                   'Sent order confirmation for A-%d to %s (message-id <%s.%d@shop.acme.com>)' % (
                       c.order_base - r.randint(0, 60), V.masked_email(), V.hexid(12), r.randint(1, 9)))

    def s_ispn(st, c):
        th = 'expiration-thread--p%d-t1' % r.randint(2, 4)
        return NUL.join([
            rec(st, 'DEBUG', 'org.infinispan.expiration.impl.ExpirationManagerImpl', th,
                'Purging data container of expired entries'),
            rec(st, 'DEBUG', 'org.infinispan.expiration.impl.ExpirationManagerImpl', th,
                'Purging data container completed in %d milliseconds' % r.randint(0, 9))])

    def s_hqlstat(st, c):
        q = r.choice(('select c from Customer c where c.email = :email',
                      'select p from Product p where p.category.slug = :slug order by p.name',
                      'select o from Order o join fetch o.items where o.orderNo = :no',
                      'select count(o) from Order o where o.customer.id = :cid and o.status = :status'))
        return rec(st, 'DEBUG', 'org.hibernate.stat.internal.StatisticsImpl', t_req(r),
                   'HHH000117: HQL: %s, time: %dms, rows: %d' % (q, V.dur(4), r.randint(0, 48)))

    def s_metrics(st, c):
        ns = lambda m: int(r.lognormvariate(math.log(m), 0.7))
        st_n = r.randint(1, 9)
        body = ('Session Metrics {\n'
                '    %d nanoseconds spent acquiring 1 JDBC connections;\n'
                '    0 nanoseconds spent releasing 0 JDBC connections;\n'
                '    %d nanoseconds spent preparing %d JDBC statements;\n'
                '    %d nanoseconds spent executing %d JDBC statements;\n'
                '    0 nanoseconds spent executing 0 JDBC batches;\n'
                '    0 nanoseconds spent performing 0 L2C puts;\n'
                '    0 nanoseconds spent performing 0 L2C hits;\n'
                '    0 nanoseconds spent performing 0 L2C misses;\n'
                '    %d nanoseconds spent executing 1 flushes (flushing a total of %d entities and %d collections);\n'
                '    0 nanoseconds spent executing 0 pre-partial-flushes;\n'
                '    0 nanoseconds spent executing 0 partial-flushes (flushing a total of 0 entities and 0 collections)\n'
                '}') % (ns(30000), ns(400000), st_n, ns(2500000), st_n, ns(900000), r.randint(1, 20), r.randint(0, 6))
        return rec(st, 'INFO', 'org.hibernate.engine.internal.StatisticalLoggingSessionEventListener', t_req(r), body)

    def s_search(st, c):
        return rec(st, 'INFO', 'com.acme.shop.catalog.SearchService', t_req(r),
                   "Search '%s' returned %d hits in %d ms (user=%s)" % (
                       r.choice(_SEARCH), r.randint(0, 400), V.dur(40), V.user()))

    # noise
    def s_loginfail(st, c):
        return rec(st, 'WARN', 'com.acme.shop.auth.LoginService', t_req(r),
                   "Failed login for user '%s' from %s (attempt %d, reason=BAD_CREDENTIALS)" % (
                       V.user(), V.ip(), r.randint(1, 5)))

    def s_multimatch(st, c):
        return rec(st, 'WARN', 'org.jboss.resteasy.resteasy_jaxrs.i18n', t_req(r),
                   'RESTEASY002142: Multiple resource methods match request "GET /products/search". Selecting one. '
                   'Matching methods: [public jakarta.ws.rs.core.Response com.acme.shop.api.ProductResource.search('
                   'java.lang.String,int,int), public jakarta.ws.rs.core.Response '
                   'com.acme.shop.api.ProductResource.searchLegacy(java.lang.String)]')

    def s_collfetch(st, c):
        return rec(st, 'WARN', 'org.hibernate.orm.query', t_req(r),
                   'HHH90003004: firstResult/maxResults specified with collection fetch; applying in memory')

    def s_jwt(st, c):
        return rec(st, 'WARN', 'com.acme.shop.security.JwtFilter', t_req(r),
                   'Rejected expired token for subject %s from %s (expired %d s ago)' % (
                       V.user(), V.ip(), r.randint(1, 90000)))

    def s_dup(st, c):
        k = r.choice(('order', 'register', 'cart'))
        th = t_req(r)
        if k == 'order':
            on = 'A-%d' % (c.order_base - r.randint(0, 50))
            pg = ('ERROR: duplicate key value violates unique constraint "orders_order_no_key"\n'
                  '  Detail: Key (order_no)=(%s) already exists.' % on)
            sql = 'insert into orders (created_at,customer_id,order_no,status,total,id) values (?,?,?,?,?,?)'
        elif k == 'register':
            pg = ('ERROR: duplicate key value violates unique constraint "uk_customer_email"\n'
                  '  Detail: Key (email)=(%s) already exists.' % V.email())
            sql = 'insert into customer (created_at,email,first_name,last_name,status,id) values (?,?,?,?,?,?)'
        else:
            pg = ('ERROR: duplicate key value violates unique constraint "uk_cart_item_product"\n'
                  '  Detail: Key (cart_id, product_id)=(%s, %d) already exists.' % (V.uuid(), V.pid()))
            sql = 'insert into cart_item (cart_id,product_id,quantity,id) values (?,?,?,?)'
        s = SCN[k]
        hib = 'org.hibernate.exception.ConstraintViolationException: could not execute statement [%s] [%s]' % (pg, sql)
        exc = TR['dup'][k].text(st, 'jakarta.ejb.EJBException: ' + hib, hib, 'org.postgresql.util.PSQLException: ' + pg)
        return NUL.join([
            rec(st, 'WARN', 'org.hibernate.engine.jdbc.spi.SqlExceptionHelper', th, 'SQL Error: 0, SQLState: 23505'),
            rec(st, 'ERROR', 'org.hibernate.engine.jdbc.spi.SqlExceptionHelper', th, pg),
            rec(st, 'ERROR', 'org.jboss.as.ejb3.invocation', th,
                'WFLYEJB0034: Jakarta Enterprise Beans Invocation failed on component %s for method %s' % (s.comp, s.sig),
                exc)])

    def s_notfound(st, c):
        p = r.choice(('/shop/api/products/%d' % r.randint(90000000, 99999999), '/shop/api/wp-login.php',
                      '/shop/api/v1/products/%d' % V.pid(), '/shop/api/cart/%s/itemz' % V.uuid(),
                      '/shop/api/.env', '/shop/api/orders/A-%d/invoice.pdf' % r.randint(100000, 999999)))
        h = 'jakarta.ws.rs.NotFoundException: RESTEASY003210: Could not find resource for full path: https://shop.acme.com%s' % p
        return rec(st, 'WARN', 'org.jboss.resteasy.resteasy_jaxrs.i18n', t_req(r), 'RESTEASY002010: Failed to execute',
                   TR['notfound'].text(st, h))

    def s_toobig(st, c):
        h = 'io.undertow.server.RequestTooBigException: UT000020: Connection terminated as request was larger than 10485760'
        return rec(st, 'ERROR', 'io.undertow.request', t_req(r),
                   'UT005023: Exception handling request to /shop/api/uploads/images', TR['toobig'].text(st, h))

    def s_pipe(st, c):
        return rec(st, 'ERROR', 'io.undertow.request', t_req(r),
                   'UT005071: Undertow request failed HttpServerExchange{ GET /shop/api/export/orders?from=%d}' % r.randint(1, 30),
                   TR['pipe'].text(st, 'java.io.IOException: Broken pipe'))

    def s_ispn_lock(st, c):
        key = 'SessionCreationMetaDataKey(%s)' % V.sess()
        h = ('org.infinispan.util.concurrent.TimeoutException: ISPN000299: Unable to acquire lock after 15 seconds '
             'for key %s and requestor GlobalTx:node1:%d. Lock is held by GlobalTx:node1:%d' % (
                 key, r.randint(10000, 99999), r.randint(10000, 99999)))
        return rec(st, 'WARN', 'org.infinispan.interceptors.impl.InvocationContextInterceptor', t_req(r),
                   "ISPN000136: Error executing command PutKeyValueCommand on Cache 'shop.war', writing keys [%s]" % key,
                   TR['ispn'].text(st, h))

    def s_arj_bg(st, c):
        tx = c.txid(r)
        return NUL.join([
            rec(st, 'WARN', 'com.arjuna.ats.arjuna', 'Transaction Reaper',
                'ARJUNA012117: TransactionReaper::check timeout for TX %s in state  RUN' % tx),
            rec(st, 'WARN', 'com.arjuna.ats.arjuna', 'Transaction Reaper Worker 0',
                'ARJUNA012121: TransactionReaper::doCancellations worker Thread[Transaction Reaper Worker 0,5,main] '
                'successfully canceled TX %s' % tx)])

    server = [
        # name, weight, fn, kind
        ('undertow.matched_prefix', 6, s_matched, 'info'),
        ('resteasy.pathinfo', 5, s_pathinfo, 'info'),
        ('app.request_log', 12, s_access, 'info'),
        ('hibernate.sql_select+binds', 14, lambda st, c: sql_record(st, c, 'select'), 'info'),
        ('hibernate.sql_insert+binds', 3, lambda st, c: sql_record(st, c, 'insert'), 'info'),
        ('hibernate.sql_update+binds', 3, lambda st, c: sql_record(st, c, 'update'), 'info'),
        ('ironjacamar.getConnection', 5, s_jca_get, 'info'),
        ('ironjacamar.returnConnection', 5, s_jca_ret, 'info'),
        ('arjuna.begin', 3, s_arj_begin, 'info'),
        ('arjuna.end', 3, s_arj_end, 'info'),
        ('app.order_placed', 2, s_order, 'info'),
        ('app.login', 1.5, s_login, 'info'),
        ('app.product_cache', 6, s_cache, 'info'),
        ('app.cart_add', 3, s_cart, 'info'),
        ('app.checkout_started', 1.5, s_checkout, 'info'),
        ('app.payment_authorized', 1.2, s_payok, 'info'),
        ('app.mail_sent', 1, s_mail, 'info'),
        ('infinispan.expiration_purge', 0.3, s_ispn, 'info'),
        ('hibernate.HHH000117_query_stats', 2, s_hqlstat, 'info'),
        ('hibernate.session_metrics', 0.6, s_metrics, 'info'),
        ('app.search', 2, s_search, 'info'),
        ('WARN app.login_failed', 0.25, s_loginfail, 'noise'),
        ('WARN RESTEASY002142 multiple resource methods', 0.12, s_multimatch, 'noise'),
        ('WARN HHH90003004 collection fetch in memory', 0.1, s_collfetch, 'noise'),
        ('WARN app.jwt_expired', 0.2, s_jwt, 'noise'),
        ('ERROR SQLState 23505 duplicate key + WFLYEJB0034 ConstraintViolationException', 0.06, s_dup, 'noise'),
        ('WARN RESTEASY002010 jakarta.ws.rs.NotFoundException', 0.10, s_notfound, 'noise'),
        ('ERROR UT005023 io.undertow.server.RequestTooBigException', 0.01, s_toobig, 'noise'),
        ('ERROR UT005071 java.io.IOException: Broken pipe', 0.05, s_pipe, 'noise'),
        ('WARN ISPN000136 org.infinispan.util.concurrent.TimeoutException', 0.008, s_ispn_lock, 'noise'),
        ('WARN ARJUNA012117/ARJUNA012121 single tx timeout', 0.004, s_arj_bg, 'noise'),
    ]

    # ---------------- log4j2 app.log ----------------
    def a_order(st, c):
        return rec(st, 'INFO', 'com.acme.shop.api.OrderResource', t_req(r),
                   'Creating order for customer %d with %d items (cart %s)' % (V.cid(), r.randint(1, 7), V.uuid()))

    def a_prod(st, c):
        return rec(st, 'DEBUG', 'com.acme.shop.catalog.ProductService', t_req(r),
                   "Loaded product %d '%s' in %d ms" % (V.pid(), r.choice(V.products), V.dur(4)))

    def a_checkout(st, c):
        return rec(st, 'INFO', 'com.acme.shop.checkout.CheckoutService', t_req(r),
                   'Cart %s checked out: %d items, total %s EUR, shipping %s to %s' % (
                       V.uuid(), r.randint(1, 7), V.price(), r.choice(_CARRIERS), r.choice(_GEO)))

    def a_jwt(st, c):
        return rec(st, 'DEBUG', 'com.acme.shop.security.JwtFilter', t_req(r),
                   'Token validated for subject %s, roles=[customer], jti=%s' % (V.user(), V.hexid(12)))

    def a_stock(st, c):
        return rec(st, 'INFO', 'com.acme.shop.inventory.StockService', t_req(r),
                   'Reserved %d x %s for order A-%d (remaining %d)' % (
                       r.randint(1, 3), V.sku(), c.order_base - r.randint(0, 30), r.randint(4, 500)))

    def a_cart(st, c):
        return rec(st, 'DEBUG', 'com.acme.shop.cart.CartService', t_req(r),
                   'Cart %s: added %s qty %d (cart size %d)' % (V.uuid(), V.sku(), r.randint(1, 3), r.randint(1, 12)))

    def a_pay(st, c):
        return rec(st, 'INFO', 'com.acme.shop.payment.PaymentService', t_pool(r),
                   'Payment authorized for order A-%d: txn=pay_%s, amount %s EUR, %d ms' % (
                       c.order_base - r.randint(0, 30), V.hexid(16), V.price(), V.dur(280, 0.4)))

    def a_price(st, c):
        base = float(V.price())
        d = r.choice((0, 0, 5, 10, 15, 20))
        return rec(st, 'DEBUG', 'com.acme.shop.pricing.PriceEngine', t_req(r),
                   'Computed price for %s: base %.2f, discount %d%%, final %.2f (rules=[%s])' % (
                       V.sku(), base, d, base * (100 - d) / 100,
                       r.choice(('TIER_PRICE', 'BLACK_WEEK', 'NEWSLETTER10', 'BUNDLE', 'NONE'))))

    def a_reg(st, c):
        return rec(st, 'INFO', 'com.acme.shop.customer.CustomerService', t_req(r),
                   'New customer registered: id=%d, email=%s, source=%s' % (
                       V.cid(), V.masked_email(), r.choice(('web', 'app-ios', 'app-android'))))

    def a_lowstock(st, c):
        return rec(st, 'WARN', 'com.acme.shop.inventory.StockService', t_req(r),
                   'Low stock for %s: %d left (threshold 5)' % (V.sku(), r.randint(0, 4)))

    def a_coupon(st, c):
        return rec(st, 'WARN', 'com.acme.shop.checkout.CouponService', t_req(r),
                   "Coupon 'XMAS-%s' rejected for customer %d: %s" % (
                       V.hexid(4).upper(), V.cid(), r.choice(('expired', 'usage limit reached', 'min order value not met'))))

    def a_jwtexp(st, c):
        return rec(st, 'WARN', 'com.acme.shop.security.JwtFilter', t_req(r),
                   'Rejected expired token for subject %s from %s' % (V.user(), V.ip()))

    def a_mail(st, c):
        h = ('jakarta.mail.MessagingException: Could not connect to SMTP host: smtp.acme.local, port: 25;\n'
             '  nested exception is:\n\tjava.net.ConnectException: Connection refused')
        return rec(st, 'ERROR', 'com.acme.shop.mail.MailService', t_pool(r),
                   'Failed to send order confirmation for A-%d to %s' % (c.order_base - r.randint(0, 60), V.masked_email()),
                   TR['mail'].text(st, h, 'java.net.ConnectException: Connection refused'))

    def a_iae(st, c):
        f = r.choice(('prize', 'nmae', 'rating desc', 'created', 'popularity;drop'))
        return rec(st, 'ERROR', 'com.acme.shop.api.ErrorMapper', t_req(r),
                   'Unhandled exception for GET /api/search?q=%s&sort=%s' % (r.choice(_SEARCH), f),
                   TR['iae'].text(st, "java.lang.IllegalArgumentException: Invalid sort field '%s'" % f))

    app = [
        ('app.order_create', 4, a_order, 'info'),
        ('app.product_loaded', 10, a_prod, 'info'),
        ('app.checkout_done', 3, a_checkout, 'info'),
        ('app.jwt_validated', 10, a_jwt, 'info'),
        ('app.stock_reserved', 4, a_stock, 'info'),
        ('app.cart_added', 6, a_cart, 'info'),
        ('app.payment_authorized', 2, a_pay, 'info'),
        ('app.price_computed', 6, a_price, 'info'),
        ('app.customer_registered', 0.5, a_reg, 'info'),
        ('WARN app.low_stock', 0.4, a_lowstock, 'noise'),
        ('WARN app.coupon_rejected', 0.3, a_coupon, 'noise'),
        ('WARN app.jwt_expired', 0.2, a_jwtexp, 'noise'),
        ('ERROR app.mail MessagingException/ConnectException', 0.03, a_mail, 'noise'),
        ('ERROR app.ErrorMapper IllegalArgumentException invalid sort field', 0.05, a_iae, 'noise'),
    ]
    return server, app


class Pool:
    """Weighted pool of pre-rendered record suffixes; slots keep their template, entries get refreshed."""

    def __init__(self, r, ctx, tpls, size, style):
        self.r, self.ctx, self.tpls, self.style = r, ctx, tpls, style
        tw = sum(t[1] for t in tpls)
        self.slots = []
        for i, t in enumerate(tpls):
            self.slots.extend([i] * max(1, int(round(t[1] / tw * size))))
        self.entries = [tpls[i][2](style, ctx) for i in self.slots]
        self.recalc()

    def refresh(self, frac):
        n = len(self.slots)
        ent, slots, tpls, st, c = self.entries, self.slots, self.tpls, self.style, self.ctx
        for j in self.r.sample(range(n), int(n * frac)):
            ent[j] = tpls[slots[j]][2](st, c)
        self.recalc()

    def recalc(self):
        n = len(self.entries)
        tot = sum(map(len, self.entries))
        nul = sum(e.count(NUL) for e in self.entries)
        self.avg_len = (tot + (n + nul) * TS_LEN) / n

    def shares(self):
        n = len(self.slots)
        cnt = {}
        for i in self.slots:
            cnt[i] = cnt.get(i, 0) + 1
        return [(self.tpls[i][0], self.tpls[i][3], cnt[i] / n) for i in sorted(cnt)]


# ======================================================================================
# output sinks
# ======================================================================================
class Sink:
    FLUSH = 8 << 20

    def __init__(self, name, budget, gz_level=None):
        self.name = name
        self.budget = budget
        self.buf = []
        self.buflen = 0
        self.written = 0      # chars (= bytes, output is ASCII)
        self.lines = 0
        self.f = None
        self.path = None
        self.files = []       # (filename, uncompressed bytes, lines)
        self._fbytes = 0
        self._flines = 0
        self.gz_level = gz_level
        self.ev = {}          # second -> [(ms, suffix)]
        self.ev_total = 0
        self.ev_used = 0
        self.kl = 0.0
        self.pool = None

    def open(self, path, gz=False):
        self.close()
        self.path = path
        self.f = gzip.open(path, 'wb', compresslevel=self.gz_level or 1) if gz else open(path, 'wb')
        self._fbytes = 0
        self._flines = 0

    def write(self, s):
        self.buf.append(s)
        self.buflen += len(s)
        if self.buflen > self.FLUSH:
            self.flush()

    def flush(self):
        if self.buf:
            data = ''.join(self.buf)
            self.buf = []
            self.buflen = 0
            n = data.count('\n')
            self.lines += n
            self._flines += n
            self._fbytes += len(data)
            self.written += len(data)
            self.f.write(data.encode('utf-8'))

    def close(self):
        if self.f:
            self.flush()
            self.f.close()
            self.files.append((os.path.basename(self.path), self._fbytes, self._flines))
            self.f = None

    def add(self, t, sfx):
        s = int(t)
        self.ev.setdefault(s, []).append((MS[min(999, int((t - s) * 1000))], sfx))

    @property
    def total_written(self):
        return self.written + self.buflen


def parse_size(s):
    m = re.fullmatch(r'\s*([0-9]+(?:\.[0-9]+)?)\s*([kKmMgGtT]?)[iI]?[bB]?\s*', s)
    if not m:
        raise argparse.ArgumentTypeError('invalid size: %r (use e.g. 500M, 2G, 300K)' % s)
    mult = {'': 1, 'k': 1 << 10, 'm': 1 << 20, 'g': 1 << 30, 't': 1 << 40}[m.group(2).lower()]
    return int(float(m.group(1)) * mult)


# ======================================================================================
# generator
# ======================================================================================
class Gen:
    def __init__(self, args):
        self.args = args
        self.r = random.Random(args.seed)
        self.D = args.days
        self.T = self.D * 86400
        if args.start:
            self.start_date = dt.date.fromisoformat(args.start)
        else:
            self.start_date = dt.date.today() - dt.timedelta(days=self.D)
        self.start_dt = dt.datetime.combine(self.start_date, dt.time())
        self.total = args.size
        self.f = min(4.0, max(0.05, self.total / (500 << 20)))   # incident intensity scale
        self.ctx = Ctx(self.start_dt)
        self.V = Vals(self.r)
        self.incidents = []
        self.alive = bytearray(b'\x01') * self.T
        self.windows = []  # (start, end) of incidents, to keep random ones apart
        con_budget = min(4 << 20, int(self.total * 0.02))
        app_budget = int(self.total * 0.20)
        self.srv = Sink('server', self.total - app_budget - con_budget, args.gzip_level)
        self.app = Sink('app', app_budget)
        self.con = Sink('console', con_budget)
        self.periodic = []

    # ---------------- time helpers ----------------
    def ts(self, t):
        d = self.start_dt + dt.timedelta(seconds=t)
        return d.strftime('%Y-%m-%d %H:%M:%S') + ',%03d' % (d.microsecond // 1000)

    def at(self, day, hh, mm, ss=0.0):
        return min(self.D - 1, max(0, day)) * 86400 + hh * 3600 + mm * 60 + ss

    def srv_file(self, t):
        d = int(t // 86400)
        if d >= self.D - 1:
            return 'server.log'
        name = 'server.log.' + (self.start_date + dt.timedelta(days=d)).isoformat()
        return name + ('.gz' if self.args.gzip_rotated else '')

    def kill(self, a, b):
        a, b = max(0, int(a)), min(self.T, int(math.ceil(b)))
        if b > a:
            self.alive[a:b] = bytes(b - a)

    def is_alive(self, t):
        return 0 <= t < self.T and self.alive[int(t)]

    # ---------------- traffic curve ----------------
    def build_curve(self):
        hw = [0.10, 0.07, 0.05, 0.05, 0.06, 0.10, 0.22, 0.45, 0.75, 0.92, 1.00, 0.97,
              0.85, 0.88, 0.95, 0.97, 0.93, 0.85, 0.75, 0.70, 0.62, 0.48, 0.30, 0.17]
        r = self.r
        w = []
        x = 0.0
        for mi in range(self.T // 60):
            day, mod = divmod(mi, 1440)
            h, m = divmod(mod, 60)
            base = hw[h] + (hw[(h + 1) % 24] - hw[h]) * m / 60.0
            wd = (self.start_date + dt.timedelta(days=day)).weekday()
            base *= (1.0, 1.0, 1.0, 1.0, 0.95, 0.6, 0.5)[wd]
            x = 0.92 * x + r.gauss(0, 0.07)
            spike = 1.0
            if r.random() < 0.002:
                spike = 1.6
            w.append(max(0.02, base * math.exp(x) * spike))
        self.w_min = w
        self.w_max = max(w)

    # ---------------- incident bookkeeping ----------------
    def incident(self, typ, desc, start, end, files, signatures, **extra):
        d = {'id': len(self.incidents) + 1, 'type': typ, 'description': desc,
             'start': self.ts(start), 'end': self.ts(end), 'start_offset_s': round(start, 3),
             'end_offset_s': round(end, 3), 'files': sorted(set(files)), 'signatures': signatures}
        d.update(extra)
        self.incidents.append(d)
        self.windows.append((start - 900, end + 900))
        return d

    def free_slot(self, day_choices, h0, h1, length):
        r = self.r
        for _ in range(500):
            t = self.at(r.choice(day_choices), r.randint(h0, h1 - 1), r.randint(0, 59), r.random() * 60)
            if t + length >= self.T:
                continue
            if all(t + length < a or t > b for a, b in self.windows) and self.is_alive(t):
                return t
        return None

    # ---------------- sequences ----------------
    def boot(self, t0, reason):
        r, s = self.r, self.srv
        k = r.uniform(0.9, 2.2)
        lines = [
            (0.00, 'org.jboss.modules', 'main', 'JBoss Modules version 2.1.2.Final'),
            (0.21, 'org.jboss.msc', 'main', 'JBoss MSC version 1.5.2.Final'),
            (0.23, 'org.jboss.threads', 'main', 'JBoss Threads version 2.4.0.Final'),
            (0.38, 'org.jboss.as', 'MSC service thread 1-2', 'WFLYSRV0049: %s starting' % WF_PRODUCT),
            (0.90, 'org.wildfly.security', 'ServerService Thread Pool -- 18', 'ELY00001: WildFly Elytron version 2.2.3.Final'),
            (1.40, 'org.jboss.as.server', 'Controller Boot Thread', 'WFLYSRV0039: Creating http management service using socket-binding (management-http)'),
            (1.42, 'org.xnio', 'MSC service thread 1-3', 'XNIO version 3.8.12.Final'),
            (1.43, 'org.xnio.nio', 'MSC service thread 1-3', 'XNIO NIO Implementation Version 3.8.12.Final'),
            (1.50, 'org.jboss.as.clustering.infinispan', 'ServerService Thread Pool -- 52', 'WFLYCLINF0001: Activating Infinispan subsystem.'),
            (1.50, 'org.jboss.as.naming', 'ServerService Thread Pool -- 58', 'WFLYNAM0001: Activating Naming Subsystem'),
            (1.51, 'org.jboss.as.jaxrs', 'ServerService Thread Pool -- 54', 'WFLYRS0016: RESTEasy version 6.2.7.Final'),
            (1.52, 'org.wildfly.extension.health', 'ServerService Thread Pool -- 50', 'WFLYHEALTH0001: Activating Base Health Subsystem'),
            (1.55, 'org.jboss.as.connector', 'MSC service thread 1-1', 'WFLYJCA0009: Starting Jakarta Connectors Subsystem (WildFly/IronJacamar 3.0.6.Final)'),
            (1.60, 'org.jboss.as.connector.subsystems.datasources', 'ServerService Thread Pool -- 37', 'WFLYJCA0004: Deploying JDBC-compliant driver class org.h2.Driver (version 2.2)'),
            (1.62, 'org.jboss.as.connector.deployers.jdbc', 'MSC service thread 1-4', 'WFLYJCA0018: Started Driver service with driver-name = postgresql'),
            (1.70, 'org.wildfly.extension.undertow', 'MSC service thread 1-4', 'WFLYUT0003: Undertow 2.3.12.Final starting'),
            (1.90, 'org.jboss.as.ejb3', 'MSC service thread 1-6', 'WFLYEJB0482: Strict pool mdb-strict-max-pool is using a max instance size of 16 (per class), which is derived from the number of CPUs on this host.'),
            (1.90, 'org.jboss.as.ejb3', 'MSC service thread 1-2', 'WFLYEJB0481: Strict pool slsb-strict-max-pool is using a max instance size of 64 (per class), which is derived from thread worker pool sizing.'),
            (2.10, 'org.wildfly.extension.undertow', 'MSC service thread 1-5', 'WFLYUT0012: Started server default-server.'),
            (2.12, 'org.wildfly.extension.undertow', 'MSC service thread 1-3', 'WFLYUT0018: Host default-host starting'),
            (2.30, 'org.wildfly.extension.undertow', 'MSC service thread 1-2', 'WFLYUT0006: Undertow HTTP listener default listening on 0.0.0.0:8080'),
            (2.32, 'org.wildfly.extension.undertow', 'MSC service thread 1-6', 'WFLYUT0006: Undertow HTTPS listener https listening on 0.0.0.0:8443'),
            (2.40, 'org.jboss.as.connector.subsystems.datasources', 'MSC service thread 1-6', 'WFLYJCA0001: Bound data source [java:jboss/datasources/ExampleDS]'),
            (2.41, 'org.jboss.as.connector.subsystems.datasources', 'MSC service thread 1-1', 'WFLYJCA0001: Bound data source [java:jboss/datasources/ShopDS]'),
            (2.50, 'org.jboss.as.server.deployment.scanner', 'MSC service thread 1-1', 'WFLYDS0013: Started FileSystemDeploymentService for directory /opt/wildfly/standalone/deployments'),
        ] + self._deploy_lines(2.6) + [
            (7.30, 'org.jboss.as.server', 'Controller Boot Thread', 'WFLYSRV0212: Resuming server'),
            (7.31, 'org.jboss.as', 'Controller Boot Thread', 'WFLYSRV0060: Http management interface listening on http://127.0.0.1:9990/management'),
            (7.31, 'org.jboss.as', 'Controller Boot Thread', 'WFLYSRV0051: Admin console listening on http://127.0.0.1:9990'),
        ]
        t_end = t0 + 7.32 * k
        started_ms = int(7.32 * k * 1000) + r.randint(500, 900)
        lines.append((7.32, 'org.jboss.as', 'Controller Boot Thread',
                      'WFLYSRV0025: %s started in %dms - Started 612 of 845 services (382 services are lazy, passive '
                      'or on-demand) - Server configuration file in use: standalone.xml' % (WF_PRODUCT, started_ms)))
        for off, lg, th, msg in lines:
            s.add(t0 + off * k, rec('wf', 'INFO', lg, th, msg))
        self.app.add(t0 + 6.9 * k, rec('l4j', 'INFO', 'com.acme.shop.ShopStartup', 'ServerService Thread Pool -- 64',
                                       'Shop application %s (build %d) started in %d ms, profile=prod' % (
                                           self.ctx.version, self.ctx.build, int(4.3 * k * 1000))))
        self.kill(t0, t_end + 1)
        return t_end

    def _deploy_lines(self, o):
        jndi = []
        for i, (bean, iface) in enumerate((('OrderService', 'com.acme.shop.OrderService'),
                                           ('CheckoutService', 'com.acme.shop.checkout.CheckoutService'),
                                           ('CartService', 'com.acme.shop.cart.CartService'),
                                           ('InventorySync', 'com.acme.shop.jobs.InventorySync'))):
            jndi.append((o + 1.3 + i * 0.01, 'org.jboss.as.ejb3.deployment', 'MSC service thread 1-6',
                         "WFLYEJB0473: JNDI bindings for session bean named '%s' in deployment unit 'deployment \"shop.war\"' are as follows:\n\n"
                         "\tjava:global/shop/%s!%s\n\tjava:app/shop/%s!%s\n\tjava:module/%s!%s\n"
                         "\tjava:global/shop/%s\n\tjava:app/shop/%s\n\tjava:module/%s\n" % (
                             bean, bean, iface, bean, iface, bean, iface, bean, bean, bean)))
        return [
            (o + 0.0, 'org.jboss.as.server.deployment', 'MSC service thread 1-3', 'WFLYSRV0027: Starting deployment of "shop.war" (runtime-name: "shop.war")'),
            (o + 0.6, 'org.infinispan.CONTAINER', 'ServerService Thread Pool -- 60', "ISPN000556: Starting user marshaller 'org.wildfly.clustering.infinispan.marshalling.jboss.JBossMarshaller'"),
            (o + 0.65, 'org.infinispan.CONTAINER', 'ServerService Thread Pool -- 60', "ISPN000128: Infinispan version: Infinispan 'Taiga' 14.0.24.Final"),
            (o + 1.0, 'org.jboss.as.jpa', 'MSC service thread 1-2', 'WFLYJPA0002: Read persistence.xml for shopPU'),
            (o + 1.1, 'org.jboss.weld.deployer', 'MSC service thread 1-6', 'WFLYWELD0003: Processing weld deployment shop.war'),
            (o + 1.15, 'org.hibernate.validator.internal.util.Version', 'MSC service thread 1-6', 'HV000001: Hibernate Validator 8.0.1.Final'),
        ] + jndi + [
            (o + 1.7, 'org.jboss.weld.Version', 'MSC service thread 1-4', 'WELD-000900: 5.1.2 (Final)'),
            (o + 1.9, 'org.hibernate.jpa.internal.util.LogHelper', 'ServerService Thread Pool -- 64', 'HHH000204: Processing PersistenceUnitInfo [name: shopPU]'),
            (o + 1.92, 'org.hibernate.Version', 'ServerService Thread Pool -- 64', 'HHH000412: Hibernate ORM core version 6.4.4.Final'),
            (o + 2.0, 'org.hibernate.cache.internal.RegionFactoryInitiator', 'ServerService Thread Pool -- 64', 'HHH000026: Second-level cache disabled'),
            (o + 2.8, 'org.jboss.as.jpa', 'ServerService Thread Pool -- 64', "WFLYJPA0010: Starting Persistence Unit (phase 2 of 2) Service 'shop.war#shopPU'"),
            (o + 4.2, 'org.jboss.resteasy.resteasy_jaxrs.i18n', 'ServerService Thread Pool -- 64', 'RESTEASY002225: Deploying jakarta.ws.rs.core.Application: class com.acme.shop.api.ShopApplication'),
            (o + 4.4, 'org.wildfly.extension.undertow', 'ServerService Thread Pool -- 64', "WFLYUT0021: Registered web context: '/shop' for server 'default-server'"),
            (o + 4.6, 'org.jboss.as.server', 'ServerService Thread Pool -- 40', 'WFLYSRV0010: Deployed "shop.war" (runtime-name : "shop.war")'),
        ]

    def shutdown(self, t0):
        r, s = self.r, self.srv
        mh = 'management-handler-thread - %d' % r.randint(1, 4)
        seq = [
            (0.00, 'org.jboss.as.server', mh, 'WFLYSRV0211: Suspending server with no timeout.'),
            (0.05, 'org.jboss.as.ejb3', mh, 'WFLYEJB0493: Jakarta Enterprise Beans subsystem suspension complete'),
            (0.10, 'org.jboss.as.server', 'Management Triggered Shutdown', "WFLYSRV0241: Shutting down in response to management operation 'shutdown'"),
            (0.15, 'org.wildfly.extension.undertow', 'ServerService Thread Pool -- 80', "WFLYUT0022: Unregistered web context: '/shop' from server 'default-server'"),
            (0.20, 'org.jboss.as.jpa', 'ServerService Thread Pool -- 80', "WFLYJPA0011: Stopping Persistence Unit (phase 2 of 2) Service 'shop.war#shopPU'"),
            (0.25, 'org.jboss.as.connector.subsystems.datasources', 'MSC service thread 1-3', 'WFLYJCA0010: Unbound data source [java:jboss/datasources/ShopDS]'),
            (0.26, 'org.jboss.as.connector.subsystems.datasources', 'MSC service thread 1-5', 'WFLYJCA0010: Unbound data source [java:jboss/datasources/ExampleDS]'),
            (0.30, 'org.wildfly.extension.undertow', 'MSC service thread 1-6', 'WFLYUT0019: Host default-host stopping'),
            (0.31, 'org.wildfly.extension.undertow', 'MSC service thread 1-2', 'WFLYUT0008: Undertow HTTP listener default suspending'),
            (0.32, 'org.wildfly.extension.undertow', 'MSC service thread 1-2', 'WFLYUT0007: Undertow HTTP listener default stopped, was bound to 0.0.0.0:8080'),
            (0.40, 'org.jboss.as.server.deployment', 'MSC service thread 1-5', 'WFLYSRV0028: Stopped deployment shop.war (runtime-name: shop.war) in %dms' % r.randint(180, 420)),
            (0.42, 'org.wildfly.extension.undertow', 'MSC service thread 1-1', 'WFLYUT0004: Undertow 2.3.12.Final stopping'),
        ]
        for off, lg, th, msg in seq:
            s.add(t0 + off, rec('wf', 'INFO', lg, th, msg))
        t_end = t0 + 0.45
        s.add(t_end, rec('wf', 'INFO', 'org.jboss.as', 'MSC service thread 1-4',
                         'WFLYSRV0050: %s stopped in %dms' % (WF_PRODUCT, r.randint(380, 700))))
        self.app.add(t0 + 0.12, rec('l4j', 'INFO', 'com.acme.shop.ShopStartup', 'ServerService Thread Pool -- 80',
                                    'Shop application %s shutting down' % self.ctx.version))
        return t_end

    # ---------------- incidents ----------------
    def inc_initial_boot(self):
        t0 = 2.0 + self.r.random()
        te = self.boot(t0, 'initial')
        self.kill(0, t0)
        self.incident('server_start', 'Initial server start sequence at the beginning of the logs', t0, te,
                      [self.srv_file(t0), 'console.log', 'app.log'],
                      [{'level': 'INFO', 'logger': 'org.jboss.as', 'code': 'WFLYSRV0049', 'message': '<product> starting'},
                       {'level': 'INFO', 'logger': 'org.jboss.as.server', 'code': 'WFLYSRV0010', 'message': 'Deployed "shop.war" (runtime-name : "shop.war")'},
                       {'level': 'INFO', 'logger': 'org.jboss.as', 'code': 'WFLYSRV0025', 'message': '<product> started in <n>ms - ...'}],
                      preceded_by_stop=None)

    def inc_clean_restart(self):
        r = self.r
        ts = self.at(self.D // 2, 3, 10 + r.randint(0, 15), r.random() * 60)
        te = self.shutdown(ts)
        down = r.uniform(45, 120)
        self.kill(ts, te + down)
        tb = te + down
        tbe = self.boot(tb, 'restart')
        self.incident('clean_restart', 'Planned restart: clean shutdown (WFLYSRV0050) followed by a normal start sequence',
                      ts, tbe, [self.srv_file(ts), 'app.log'],
                      [{'level': 'INFO', 'logger': 'org.jboss.as.server', 'code': 'WFLYSRV0241', 'message': "Shutting down in response to management operation 'shutdown'"},
                       {'level': 'INFO', 'logger': 'org.jboss.as', 'code': 'WFLYSRV0050', 'message': '<product> stopped in <n>ms'},
                       {'level': 'INFO', 'logger': 'org.jboss.as', 'code': 'WFLYSRV0049', 'message': '<product> starting'},
                       {'level': 'INFO', 'logger': 'org.jboss.as', 'code': 'WFLYSRV0025', 'message': '<product> started in <n>ms - ...'}],
                      stopped_at=self.ts(te), restarted_at=self.ts(tb), downtime_s=round(down, 1))

    def inc_pool_exhaustion(self):
        r, s, V, c = self.r, self.srv, self.V, self.ctx
        day = min(self.D - 1, int(self.D * 0.15))
        t0 = self.at(day, 9, 50 + r.randint(-10, 10), r.random() * 60)
        dur = 15 * 60 + r.uniform(-60, 60)
        t_slow = t0 - 6 * 60 - r.uniform(0, 60)
        t_reap = t0 - 2 * 60 - r.uniform(0, 30)
        t_end = t0 + dur
        f = self.f
        # root cause: slow report queries
        n_slow = 0
        t = t_slow
        while t < t_end + 60:
            prog = (t - t_slow) / (t_end - t_slow)
            ms_ = int(4000 + prog * 56000 * r.uniform(0.6, 1.2))
            s.add(t, rec('wf', 'WARN', 'com.acme.shop.repo.ReportRepository', t_ejb(r),
                         'Slow query detected (%d ms) for report MonthlySalesReport [from=2025-%02d-01, rows=%d, user=%s]: '
                         'select oi1_0.product_id,sum(oi1_0.quantity),sum(oi1_0.price*oi1_0.quantity) from order_item oi1_0 '
                         'join orders o1_0 on o1_0.id=oi1_0.order_id where o1_0.created_at between ? and ? group by oi1_0.product_id' % (
                             ms_, r.randint(1, 12), r.randint(20000, 900000), r.choice(('controller7', 'finance.bot', 'm.huber')))))
            n_slow += 1
            t += r.uniform(8, 30)
        # transaction reaper timeouts start a bit before the pool runs dry
        n_reap = 0
        t = t_reap
        while t < t_end:
            tx = c.txid(r)
            s.add(t, rec('wf', 'WARN', 'com.arjuna.ats.arjuna', 'Transaction Reaper',
                         'ARJUNA012117: TransactionReaper::check timeout for TX %s in state  RUN' % tx))
            s.add(t + r.uniform(0.002, 0.05), rec('wf', 'WARN', 'com.arjuna.ats.arjuna', 'Transaction Reaper Worker 0',
                         'ARJUNA012121: TransactionReaper::doCancellations worker Thread[Transaction Reaper Worker 0,5,main] '
                         'successfully canceled TX %s' % tx))
            n_reap += 1
            t += r.expovariate((0.3 + 1.2 * f) if t >= t0 else 0.25)
        # connection pool exhaustion burst
        peak = max(0.15, 1.0 * f)
        n_ij = 0
        t = t0
        first = None
        last = t0
        while t < t_end:
            ramp = min(1.0, (t - t0) / 60.0, (t_end - t) / 90.0 + 0.1)
            if first is None:
                first = t
            k = r.choice(('order', 'catalog', 'cart', 'checkout'))
            sc = SCN[k]
            th = t_req(r)
            ij = 'jakarta.resource.ResourceException: IJ000453: Unable to get managed connection for java:jboss/datasources/ShopDS'
            sq = 'java.sql.SQLException: ' + ij
            hib = 'org.hibernate.exception.JDBCConnectionException: Unable to acquire JDBC Connection [%s] [n/a]' % ij
            exc = TR['ij'][k].text('wf', 'jakarta.ejb.EJBException: ' + hib, hib, sq, ij,
                                   'jakarta.resource.ResourceException: IJ000655: No managed connections available within configured blocking timeout (30000 [ms])')
            s.add(t, rec('wf', 'WARN', 'org.hibernate.engine.jdbc.spi.SqlExceptionHelper', th, 'SQL Error: 0, SQLState: null'))
            s.add(t + 0.001, rec('wf', 'ERROR', 'org.hibernate.engine.jdbc.spi.SqlExceptionHelper', th, ij))
            s.add(t + 0.003, rec('wf', 'ERROR', 'org.jboss.as.ejb3.invocation', th,
                                 'WFLYEJB0034: Jakarta Enterprise Beans Invocation failed on component %s for method %s' % (sc.comp, sc.sig), exc))
            if r.random() < 0.15:
                self.app.add(t + 0.004, rec('l4j', 'ERROR', 'com.acme.shop.api.ErrorMapper', th,
                                            'Request %s failed: database unavailable' % sc.path,
                                            TR['ij'][k].text('l4j', 'jakarta.ejb.EJBException: ' + hib, hib, sq, ij,
                                                             'jakarta.resource.ResourceException: IJ000655: No managed connections available within configured blocking timeout (30000 [ms])')))
            n_ij += 1
            last = t
            t += r.expovariate(peak * max(0.05, ramp))
        s.add(t_end + 30, rec('wf', 'INFO', 'com.acme.shop.repo.ReportRepository', 'EJB default - 2',
                              'Report job MonthlySalesReport cancelled by admin (running for %d s)' % int(t_end + 30 - t_slow)))
        self.incident('db_pool_exhaustion',
                      'ShopDS connection pool exhausted for ~15 min (IJ000453 -> JDBCConnectionException -> WFLYEJB0034); '
                      'root cause: slow ReportRepository queries starting minutes earlier; ARJUNA012117/012121 reaper '
                      'timeouts start shortly before the burst',
                      first, last, [self.srv_file(first), 'app.log'],
                      [{'level': 'WARN', 'logger': 'com.acme.shop.repo.ReportRepository', 'message': 'Slow query detected (<n> ms) for report MonthlySalesReport ...', 'count': n_slow, 'first': self.ts(t_slow), 'role': 'root_cause'},
                       {'level': 'WARN', 'logger': 'com.arjuna.ats.arjuna', 'code': 'ARJUNA012117', 'count': n_reap, 'first': self.ts(t_reap), 'role': 'precursor'},
                       {'level': 'WARN', 'logger': 'com.arjuna.ats.arjuna', 'code': 'ARJUNA012121', 'count': n_reap, 'first': self.ts(t_reap), 'role': 'precursor'},
                       {'level': 'ERROR', 'logger': 'org.hibernate.engine.jdbc.spi.SqlExceptionHelper', 'code': 'IJ000453', 'exception': 'jakarta.resource.ResourceException', 'message': 'IJ000453: Unable to get managed connection for java:jboss/datasources/ShopDS', 'count': n_ij},
                       {'level': 'ERROR', 'logger': 'org.jboss.as.ejb3.invocation', 'code': 'WFLYEJB0034', 'exception': 'jakarta.ejb.EJBException / org.hibernate.exception.JDBCConnectionException', 'count': n_ij}],
                      root_cause_start=self.ts(t_slow))

    def inc_redeploy_npe(self):
        r, s, c = self.r, self.srv, self.ctx
        day = min(1, self.D - 1)
        t0 = self.at(day, 7, 40 + r.randint(0, 10), r.random() * 60)
        th = 'ServerService Thread Pool -- %d' % r.randint(85, 99)
        seq = [
            (0.0, 'org.jboss.as.server.deployment.scanner', 'DeploymentScanner-threads - 2', "WFLYDS0004: Found shop.war in deployment directory. To trigger deployment create a file called shop.war.dodeploy"),
            (0.4, 'org.wildfly.extension.undertow', th, "WFLYUT0022: Unregistered web context: '/shop' from server 'default-server'"),
            (0.5, 'org.jboss.as.jpa', th, "WFLYJPA0011: Stopping Persistence Unit (phase 2 of 2) Service 'shop.war#shopPU'"),
            (0.8, 'org.jboss.as.server.deployment', 'MSC service thread 1-3', 'WFLYSRV0028: Stopped deployment shop.war (runtime-name: shop.war) in %dms' % r.randint(150, 400)),
        ] + [(o + 0.4, lg, t, m) for o, lg, t, m in self._deploy_lines(0.6)] + [
            (5.9, 'org.jboss.as.server', 'DeploymentScanner-threads - 2', 'WFLYSRV0016: Replaced deployment "shop.war" with deployment "shop.war"'),
        ]
        for off, lg, t, msg in seq:
            s.add(t0 + off, rec('wf', 'INFO', lg, t, msg))
        self.app.add(t0 + 0.45, rec('l4j', 'INFO', 'com.acme.shop.ShopStartup', th, 'Shop application %s shutting down' % c.version))
        self.kill(t0 + 0.3, t0 + 6)
        self.redeploy_t = t0 + 6
        c_new_version = '2.15.0'
        self.app.add(t0 + 5.0, rec('l4j', 'INFO', 'com.acme.shop.ShopStartup', th,
                                   'Shop application %s (build %d) started in %d ms, profile=prod' % (c_new_version, c.build + 37, r.randint(3000, 4500))))
        self.incident('redeployment', 'Hot redeployment of shop.war (new version 2.15.0) via deployment scanner',
                      t0, t0 + 5.9, [self.srv_file(t0), 'app.log'],
                      [{'level': 'INFO', 'logger': 'org.jboss.as.server.deployment', 'code': 'WFLYSRV0028'},
                       {'level': 'INFO', 'logger': 'org.jboss.as.server.deployment', 'code': 'WFLYSRV0027'},
                       {'level': 'INFO', 'logger': 'org.jboss.as.server', 'code': 'WFLYSRV0016', 'message': 'Replaced deployment "shop.war" with deployment "shop.war"'}],
                      new_version=c_new_version)
        self.npe_from = t0 + 6 + r.uniform(60, 400)

    def place_npe(self):
        """Must run after all downtimes are known (needs alive[])."""
        r, s = self.r, self.srv
        t = self.npe_from
        n = 0
        first = last = None
        tr = TR['npe']
        msg = 'Cannot invoke "com.acme.shop.model.Customer.getAddress()" because "customer" is null'
        sc = SCN['checkout']
        while t < self.T:
            mi = int(t // 60)
            rate = 0.08 * self.w_min[mi] / self.w_max + 0.004  # per minute
            if first is None or r.random() < rate:
                tt = int(t) + r.random()
                if self.is_alive(tt):
                    th = t_req(r)
                    npe = 'java.lang.NullPointerException: ' + msg
                    s.add(tt, rec('wf', 'ERROR', 'org.jboss.as.ejb3.invocation', th,
                                  'WFLYEJB0034: Jakarta Enterprise Beans Invocation failed on component %s for method %s' % (sc.comp, sc.sig),
                                  tr.text('wf', 'jakarta.ejb.EJBException: ' + npe, npe)))
                    self.app.add(tt + 0.002, rec('l4j', 'ERROR', 'com.acme.shop.api.CheckoutResource', th,
                                                 'Shipping quote failed for cart %s (guest checkout)' % self.V.uuid(),
                                                 tr.text('l4j', 'jakarta.ejb.EJBException: ' + npe, npe)))
                    n += 1
                    first = first if first is not None else tt
                    last = tt
            t += 60
        if first is None:
            return
        self.incident('new_error_type',
                      'Brand-new error after the redeployment: NullPointerException in ShippingCalculator, keeps occurring at a low rate until the end',
                      first, last, [self.srv_file(first), 'app.log'] + sorted({self.srv_file(x) for x in (first, last)}),
                      [{'level': 'ERROR', 'logger': 'org.jboss.as.ejb3.invocation', 'code': 'WFLYEJB0034',
                        'exception': 'java.lang.NullPointerException', 'message': msg,
                        'frame': 'com.acme.shop.checkout.ShippingCalculator.calculate(ShippingCalculator.java:61)', 'count': n},
                       {'level': 'ERROR', 'logger': 'com.acme.shop.api.CheckoutResource', 'file': 'app.log',
                        'exception': 'java.lang.NullPointerException', 'count': n}],
                      first_seen_after_redeploy_s=round(first - self.redeploy_t, 1))

    def inc_hang(self):
        r, s, c, V = self.r, self.srv, self.ctx, self.V
        day = min(self.D - 1, int(self.D * 0.5))
        t0 = self.at(day, 14, 5 + r.randint(0, 25), r.random() * 60)
        gap = 20 * 60 + r.uniform(-30, 30)
        self.kill(t0, t0 + gap)
        t1 = t0 + gap
        f = self.f
        burst = r.uniform(100, 160)
        cnt = {'ARJUNA012117': 0, 'rollback': 0, 'permit': 0, 'reject': 0}
        n_tx = int(40 + 80 * f)
        for i in range(n_tx):
            t = t1 + (i / n_tx) ** 2 * 25 + r.random() * 0.3
            tx = c.txid(r)
            s.add(t, rec('wf', 'WARN', 'com.arjuna.ats.arjuna', 'Transaction Reaper',
                         'ARJUNA012117: TransactionReaper::check timeout for TX %s in state  RUN' % tx))
            s.add(t + 0.004, rec('wf', 'WARN', 'com.arjuna.ats.arjuna', 'Transaction Reaper Worker 0',
                                 'ARJUNA012121: TransactionReaper::doCancellations worker Thread[Transaction Reaper Worker 0,5,main] successfully canceled TX %s' % tx))
            cnt['ARJUNA012117'] += 1
        for i in range(int(30 + 120 * f)):
            t = t1 + r.random() ** 1.5 * burst
            k = r.choice(('order', 'cart', 'checkout'))
            sc = SCN[k]
            rb = 'jakarta.transaction.RollbackException: ARJUNA016102: The transaction is not active! Uid is %s' % c.txid(r)
            s.add(t, rec('wf', 'ERROR', 'org.jboss.as.ejb3.invocation', t_req(r),
                         'WFLYEJB0034: Jakarta Enterprise Beans Invocation failed on component %s for method %s' % (sc.comp, sc.sig),
                         TR['rollback'][k].text('wf', 'jakarta.ejb.EJBTransactionRolledbackException: Transaction rolled back', rb)))
            cnt['rollback'] += 1
        for i in range(int(15 + 60 * f)):
            t = t1 + r.random() ** 2 * burst
            k = r.choice(('order', 'catalog', 'cart'))
            sc = SCN[k]
            s.add(t, rec('wf', 'ERROR', 'org.jboss.as.ejb3.invocation', t_req(r),
                         'WFLYEJB0034: Jakarta Enterprise Beans Invocation failed on component %s for method %s' % (sc.comp, sc.sig),
                         TR['permit'][k].text('wf', 'jakarta.ejb.EJBException: WFLYEJB0378: Failed to acquire a permit within 5 MINUTES')))
            cnt['permit'] += 1
        for i in range(int(10 + 50 * f)):
            t = t1 + r.random() ** 3 * burst
            s.add(t, rec('wf', 'ERROR', 'org.xnio.listener', t_io(r),
                         'XNIO001007: A channel event listener threw an exception',
                         TR['reject'].text('wf', 'java.util.concurrent.RejectedExecutionException: Task io.undertow.server.HttpServerExchange$1@%s '
                                                 'rejected from org.jboss.threads.EnhancedQueueExecutor@%s (queue full: 1000 tasks)' % (V.hexid(7), V.hexid(7)))))
            cnt['reject'] += 1
        s.add(t1 + burst + 5, rec('wf', 'WARN', 'com.acme.shop.jobs.InventorySync', t_ejb(r),
                                  'Previous inventory sync did not finish within 60000 ms, skipping run'))
        self.incident('silence_gap',
                      'Server hang: no log lines at all in any file for ~20 min during business hours, followed by a burst of '
                      'transaction timeouts, rolled back transactions, EJB pool permit timeouts and rejected requests',
                      t0, t1 + burst, [self.srv_file(t0), 'app.log'],
                      [{'level': 'WARN', 'logger': 'com.arjuna.ats.arjuna', 'code': 'ARJUNA012117', 'count': cnt['ARJUNA012117']},
                       {'level': 'WARN', 'logger': 'com.arjuna.ats.arjuna', 'code': 'ARJUNA012121', 'count': cnt['ARJUNA012117']},
                       {'level': 'ERROR', 'logger': 'org.jboss.as.ejb3.invocation', 'code': 'WFLYEJB0034', 'exception': 'jakarta.ejb.EJBTransactionRolledbackException / ARJUNA016102', 'count': cnt['rollback']},
                       {'level': 'ERROR', 'logger': 'org.jboss.as.ejb3.invocation', 'code': 'WFLYEJB0034', 'exception': 'jakarta.ejb.EJBException: WFLYEJB0378', 'count': cnt['permit']},
                       {'level': 'ERROR', 'logger': 'org.xnio.listener', 'code': 'XNIO001007', 'exception': 'java.util.concurrent.RejectedExecutionException', 'count': cnt['reject']}],
                      silence_start=self.ts(t0), silence_end=self.ts(t1), silence_s=round(gap, 1))

    def inc_storm(self):
        r, s, c = self.r, self.srv, self.ctx
        day = min(self.D - 1, int(self.D * 0.75))
        t0 = self.at(day, 11, 25 + r.randint(0, 15), r.random() * 60)
        dur = 180 + r.uniform(-15, 15)
        n = int(max(300, 5000 * self.f))
        tr = TR['pay']
        n_ejb = n_app = 0
        last = t0
        for i in range(n):
            u = r.random()
            t = t0 + dur * (u ** 0.8)
            last = max(last, t)
            on = c.order_base - r.randint(0, 300)
            th = t_pool(r)
            att = r.randint(1, 3)
            h = 'jakarta.ws.rs.ProcessingException: RESTEASY004655: Unable to invoke request: java.net.SocketTimeoutException: Read timed out'
            s.add(t, rec('wf', 'WARN', 'com.acme.shop.payment.PaymentGatewayClient', th,
                         'Payment authorization failed for order A-%d (attempt %d/3, endpoint=https://api.payments.example.net/v2/authorize, readTimeout=5000 ms)' % (on, att),
                         tr.text('wf', h, 'java.net.SocketTimeoutException: Read timed out')))
            if att == 3:
                s.add(t + 0.002, rec('wf', 'ERROR', 'com.acme.shop.payment.PaymentService', th,
                                     'Payment for order A-%d failed after 3 attempts, order moved to PAYMENT_PENDING' % on))
                n_ejb += 1
            if r.random() < 0.3:
                self.app.add(t + 0.003, rec('l4j', 'ERROR', 'com.acme.shop.payment.PaymentGatewayClient', th,
                                            'Gateway call failed for order A-%d' % on,
                                            tr.text('l4j', h, 'java.net.SocketTimeoutException: Read timed out')))
                n_app += 1
        self.incident('error_storm',
                      '~3 min storm of outbound REST client timeouts (payment gateway): thousands of SocketTimeoutException',
                      t0, last, [self.srv_file(t0), 'app.log'],
                      [{'level': 'WARN', 'logger': 'com.acme.shop.payment.PaymentGatewayClient', 'code': 'RESTEASY004655',
                        'exception': 'jakarta.ws.rs.ProcessingException / java.net.SocketTimeoutException: Read timed out', 'count': n},
                       {'level': 'ERROR', 'logger': 'com.acme.shop.payment.PaymentService', 'message': 'Payment for order <id> failed after 3 attempts, order moved to PAYMENT_PENDING', 'count': n_ejb},
                       {'level': 'ERROR', 'logger': 'com.acme.shop.payment.PaymentGatewayClient', 'file': 'app.log', 'exception': 'java.net.SocketTimeoutException', 'count': n_app}])

    def inc_oom_crash(self):
        r, s = self.r, self.srv
        day = min(self.D - 1, int(self.D * 0.15))
        tc = self.at(day, 16, 45 + r.randint(0, 10), r.random() * 60)
        win = 360
        n = int(25 + 60 * self.f)
        cnt = {'ut': 0, 'ejb': 0, 'stderr': 0}
        times = sorted(tc - win * (r.random() ** 2.2) for _ in range(n))
        times[-1] = tc
        stderr_at = times[len(times) // 3]
        for t in times:
            if t == stderr_at:
                lines = ['Exception in thread "Timer-1" java.lang.OutOfMemoryError: Java heap space'] + [_wf(fr) for fr in TR['oom_timer']]
                for j, ln in enumerate(lines):
                    s.add(t + j * 0.0005, rec('wf', 'ERROR', 'stderr', 'Timer-1', ln))
                cnt['stderr'] += 1
            elif r.random() < 0.6:
                s.add(t, rec('wf', 'ERROR', 'io.undertow.request', t_req(r),
                             'UT005023: Exception handling request to /shop/api/export/orders',
                             TR['oom_ut'].text('wf', 'java.lang.OutOfMemoryError: Java heap space')))
                cnt['ut'] += 1
            else:
                sc = SCN['report']
                s.add(t, rec('wf', 'ERROR', 'org.jboss.as.ejb3.invocation', t_req(r),
                             'WFLYEJB0034: Jakarta Enterprise Beans Invocation failed on component %s for method %s' % (sc.comp, sc.sig),
                             TR['oom_ejb'].text('wf', 'jakarta.ejb.EJBException: java.lang.OutOfMemoryError: Java heap space',
                                                'java.lang.OutOfMemoryError: Java heap space')))
                cnt['ejb'] += 1
        self.timer1_dead = (stderr_at, tc)
        down = r.uniform(90, 240)
        self.kill(tc + 0.01, tc + down)
        tb = tc + down
        tbe = self.boot(tb, 'after-crash')
        self.incident('crash_restart',
                      'JVM crash after java.lang.OutOfMemoryError: Java heap space errors; restart sequence WITHOUT a preceding WFLYSRV0050 (no clean shutdown)',
                      times[0], tbe, [self.srv_file(tc), 'app.log'],
                      [{'level': 'ERROR', 'logger': 'io.undertow.request', 'code': 'UT005023', 'exception': 'java.lang.OutOfMemoryError: Java heap space', 'count': cnt['ut']},
                       {'level': 'ERROR', 'logger': 'org.jboss.as.ejb3.invocation', 'code': 'WFLYEJB0034', 'exception': 'java.lang.OutOfMemoryError: Java heap space', 'count': cnt['ejb']},
                       {'level': 'ERROR', 'logger': 'stderr', 'message': 'Exception in thread "Timer-1" java.lang.OutOfMemoryError: Java heap space (stack trace logged line by line via stderr)', 'count': cnt['stderr']},
                       {'level': 'INFO', 'logger': 'org.jboss.as', 'code': 'WFLYSRV0049', 'message': 'start without preceding WFLYSRV0050'}],
                      last_line_before_crash=self.ts(tc), restarted_at=self.ts(tb), downtime_s=round(down, 1))

    def inc_rare(self):
        r, s, c = self.r, self.srv, self.ctx
        days = list(range(self.D))
        # StackOverflowError, 2-3 times
        k = r.randint(2, 3)
        sof = []
        for i in range(k):
            t = self.free_slot(days, 9, 19, 5)
            if t is None:
                continue
            cat = r.randint(3, 120)
            s.add(t, rec('wf', 'ERROR', 'io.undertow.request', t_req(r),
                         'UT005023: Exception handling request to /shop/api/categories/%d/tree' % cat,
                         TR['soe'].text('wf', 'org.jboss.resteasy.spi.UnhandledException: java.lang.StackOverflowError', 'java.lang.StackOverflowError')))
            sof.append(t)
            self.windows.append((t - 600, t + 600))
        for t in sof:
            self.incident('stack_overflow', 'Single java.lang.StackOverflowError (1024-frame recursive trace in CategoryTreeBuilder)',
                          t, t, [self.srv_file(t)],
                          [{'level': 'ERROR', 'logger': 'io.undertow.request', 'code': 'UT005023',
                            'exception': 'org.jboss.resteasy.spi.UnhandledException / java.lang.StackOverflowError',
                            'frame': 'com.acme.shop.catalog.CategoryTreeBuilder.addChildren(CategoryTreeBuilder.java:48)', 'count': 1}])
        # deadlocks, 2 times
        for i in range(2):
            t = self.free_slot(days, 9, 19, 5)
            if t is None:
                continue
            th = t_req(r)
            p1, p2 = r.randint(20000, 40000), r.randint(20000, 40000)
            x1, x2 = r.randint(9000000, 9900000), r.randint(9000000, 9900000)
            pg = ('ERROR: deadlock detected\n'
                  '  Detail: Process %d waits for ShareLock on transaction %d; blocked by process %d.\n'
                  'Process %d waits for ShareLock on transaction %d; blocked by process %d.\n'
                  '  Hint: See server log for query details.\n'
                  '  Where: while updating tuple (%d,%d) in relation "product"' % (p1, x1, p2, p2, x2, p1, r.randint(1, 900), r.randint(1, 40)))
            sql = 'update product set stock=?,version=? where id=? and version=?'
            hib = 'org.hibernate.exception.LockAcquisitionException: could not execute statement [%s] [%s]' % (pg, sql)
            sc = SCN['reserve']
            s.add(t, rec('wf', 'WARN', 'org.hibernate.engine.jdbc.spi.SqlExceptionHelper', th, 'SQL Error: 0, SQLState: 40P01'))
            s.add(t + 0.001, rec('wf', 'ERROR', 'org.hibernate.engine.jdbc.spi.SqlExceptionHelper', th, pg))
            s.add(t + 0.004, rec('wf', 'ERROR', 'org.jboss.as.ejb3.invocation', th,
                                 'WFLYEJB0034: Jakarta Enterprise Beans Invocation failed on component %s for method %s' % (sc.comp, sc.sig),
                                 TR['deadlock'].text('wf', 'jakarta.ejb.EJBException: ' + hib, hib, 'org.postgresql.util.PSQLException: ' + pg)))
            self.windows.append((t - 600, t + 600))
            self.incident('deadlock', 'Database deadlock (PostgreSQL SQLState 40P01) -> Hibernate LockAcquisitionException',
                          t, t + 0.004, [self.srv_file(t)],
                          [{'level': 'WARN', 'logger': 'org.hibernate.engine.jdbc.spi.SqlExceptionHelper', 'message': 'SQL Error: 0, SQLState: 40P01', 'count': 1},
                           {'level': 'ERROR', 'logger': 'org.hibernate.engine.jdbc.spi.SqlExceptionHelper', 'message': 'ERROR: deadlock detected ...', 'count': 1},
                           {'level': 'ERROR', 'logger': 'org.jboss.as.ejb3.invocation', 'code': 'WFLYEJB0034', 'exception': 'org.hibernate.exception.LockAcquisitionException', 'count': 1}])

    def periodic_jobs(self):
        r, s = self.r, self.srv
        hb_stop = self.T - 6 * 3600 + r.uniform(-1200, 1200)
        last = None
        n = 0
        for m in range(self.T // 60):
            t = m * 60 + 0.002 + r.random() * 0.02
            if t >= hb_stop:
                break
            d = self.V.dur(120, 0.35)
            if not (self.is_alive(t) and self.is_alive(t + d / 1000.0)):
                continue
            th = 'EJB default - %d' % r.randint(1, 16)
            s.add(t, rec('wf', 'DEBUG', 'com.acme.shop.jobs.InventorySync', th, 'Inventory sync started (warehouse=WH-%d)' % r.randint(1, 3)))
            s.add(t + d / 1000.0, rec('wf', 'INFO', 'com.acme.shop.jobs.InventorySync', th,
                                      'Inventory sync finished in %d ms, %d items updated' % (d, r.randint(0, 120))))
            last = t + d / 1000.0
            n += 1
        self.incident('heartbeat_stopped',
                      'The 60 s heartbeat job com.acme.shop.jobs.InventorySync silently stops logging for the last ~6 hours',
                      last, self.T - 0.001, ['server.log'],
                      [{'level': 'INFO', 'logger': 'com.acme.shop.jobs.InventorySync', 'message': 'Inventory sync finished in <n> ms, <n> items updated',
                        'period_s': 60, 'count': n}],
                      last_heartbeat=self.ts(last), expected_next=self.ts(last + 60))
        # other periodic jobs (keep running): ExchangeRateUpdater on Timer-1 (dies with the OOM), CacheWarmer in app.log
        dead_from, dead_to = getattr(self, 'timer1_dead', (self.T, self.T))
        for m in range(0, self.T // 60, 15):
            t = m * 60 + 7.3 + r.random() * 0.5
            if self.is_alive(t) and not (dead_from <= t < dead_to):
                s.add(t, rec('wf', 'INFO', 'com.acme.shop.legacy.ExchangeRateUpdater', 'Timer-1',
                             'Updated %d exchange rates from ECB in %d ms' % (r.randint(30, 33), self.V.dur(400, 0.3))))
        for m in range(0, self.T // 60, 5):
            t = m * 60 + 30.1 + r.random() * 0.2
            if self.is_alive(t):
                self.app.add(t, rec('l4j', 'INFO', 'com.acme.shop.cache.CacheWarmer', 'scheduler-1',
                                    'Cache warm-up finished: %d products, %d categories in %d ms' % (
                                        r.randint(9000, 12000), r.randint(120, 140), self.V.dur(900, 0.3))))
        self.periodic = [
            {'logger': 'com.acme.shop.jobs.InventorySync', 'file': 'server.log*', 'period_s': 60, 'stops_at': self.ts(last)},
            {'logger': 'com.acme.shop.legacy.ExchangeRateUpdater', 'file': 'server.log*', 'thread': 'Timer-1', 'period_s': 900,
             'note': 'skips runs while the server is down; does not run between the Timer-1 OOM and the crash restart'},
            {'logger': 'com.acme.shop.cache.CacheWarmer', 'file': 'app.log', 'period_s': 300},
        ]

    # ---------------- main loop ----------------
    def run(self):
        a = self.args
        t_start = time.time()
        os.makedirs(a.out, exist_ok=True)
        for fn in os.listdir(a.out):
            if re.fullmatch(r'server\.log(\.\d{4}-\d\d-\d\d(\.gz)?)?|app\.log|console\.log|ground_truth\.json', fn):
                os.remove(os.path.join(a.out, fn))
        self.build_curve()
        # incidents (order matters: downtimes first, then things that depend on alive[])
        self.inc_initial_boot()
        self.inc_clean_restart()
        self.inc_pool_exhaustion()
        self.inc_oom_crash()
        self.inc_redeploy_npe()
        self.inc_hang()
        self.inc_storm()
        self.inc_rare()
        self.periodic_jobs()
        self.place_npe()
        self.incidents.sort(key=lambda d: d['start_offset_s'])
        for i, d in enumerate(self.incidents, 1):
            d['id'] = i

        # effective weights per minute (0 while down)
        alive = self.alive
        w_eff = [self.w_min[mi] * alive[mi * 60:(mi + 1) * 60].count(1) / 60.0 for mi in range(self.T // 60)]
        srv, app, con = self.srv, self.app, self.con
        for sk in (srv, app):
            sk.ev_total = sum(len(x) + TS_LEN * (1 + x.count(NUL)) for lst in sk.ev.values() for _, x in lst)
        # pools
        tpl_srv, tpl_app = build_templates(self.V)
        psize = int(min(40000, max(4000, self.total / 25000)))
        srv.pool = Pool(self.r, self.ctx, tpl_srv, psize, 'wf')
        app.pool = Pool(self.r, self.ctx, tpl_app, max(2000, psize // 3), 'l4j')
        self.tpl_shares = {'server': srv.pool.shares(), 'app': app.pool.shares()}

        app.open(os.path.join(a.out, 'app.log'))
        con.open(os.path.join(a.out, 'console.log'))
        con.write('=========================================================================\n\n'
                  '  JBoss Bootstrap Environment\n\n'
                  '  JBOSS_HOME: /opt/wildfly\n\n'
                  '  JAVA: /usr/lib/jvm/java-21-openjdk/bin/java\n\n'
                  '  JAVA_OPTS:  -server -Xms2g -Xmx2g -XX:MetaspaceSize=96M -XX:MaxMetaspaceSize=512m '
                  '-Djava.net.preferIPv4Stack=true -Djboss.modules.system.pkgs=org.jboss.byteman '
                  '-Djava.awt.headless=true --add-exports=java.desktop/sun.awt=ALL-UNNAMED\n\n'
                  '=========================================================================\n\n')
        # console sampling: a few MB of INFO+ lines from day 0
        day0_w = sum(w_eff[:1440])
        W_rem = sum(w_eff)
        rnd = self.r.random
        choices = self.r.choices
        ms_all = MS
        n_min = self.T // 60
        last_prog = time.time()
        p_con = 1.0
        boot_end = int(self.incidents[0]['end_offset_s']) + 2
        con_w_rem = day0_w
        for mi in range(n_min):
            base = mi * 60
            day, mod = divmod(mi, 1440)
            if mod == 0:
                dstr = (self.start_date + dt.timedelta(days=day)).isoformat()
                if day == self.D - 1:
                    srv.open(os.path.join(a.out, 'server.log'))
                else:
                    srv.open(os.path.join(a.out, 'server.log.' + dstr + ('.gz' if a.gzip_rotated else '')),
                             gz=a.gzip_rotated)
                pre_sp = dstr + ' '
            if mi and mi % 60 == 0:
                self.ctx.t = base
                srv.pool.refresh(0.08)
                app.pool.refresh(0.08)
                if not a.quiet and time.time() - last_prog > 2:
                    last_prog = time.time()
                    done = srv.total_written + app.total_written + con.total_written
                    sys.stderr.write('\r  %5.1f%%  %s  %.0f MB  %.1f MB/s   ' % (
                        100.0 * mi / n_min, dstr, done / 1e6, done / 1e6 / (time.time() - t_start)))
                    sys.stderr.flush()
            for sk in (srv, app):
                rem = sk.budget - sk.total_written - (sk.ev_total - sk.ev_used)
                sk.kl = max(0.0, rem) / max(W_rem, 1e-9) / 60.0 / sk.pool.avg_len if W_rem > 0 else 0.0
            if day == 0:
                rem_c = con.budget - con.total_written
                exp_c = con_w_rem * srv.kl * 60 * srv.pool.avg_len * 0.55
                p_con = min(1.0, max(0.0, rem_c / exp_c)) if exp_c > 0 else 1.0
                con_w_rem -= w_eff[mi]
            W_rem -= w_eff[mi]
            wm = self.w_min[mi]
            sod0 = mod * 60
            for sec in range(60):
                s = base + sec
                al = alive[s]
                hms = HMS[sod0 + sec]
                # ---- server.log ----
                p = pre_sp + hms + ','
                items = srv.ev.pop(s, None)
                n = int(wm * srv.kl * (0.6 + 0.8 * rnd()) + rnd()) if al else 0
                if n:
                    ms = sorted(choices(ms_all, k=n))
                    sf = choices(srv.pool.entries, k=n)
                    if items:
                        srv.ev_used += sum(len(x) + TS_LEN for _, x in items)
                        pairs = sorted(list(zip(ms, sf)) + items, key=itemgetter(0))
                        ms = [q[0] for q in pairs]
                        sf = [q[1] for q in pairs]
                elif items:
                    srv.ev_used += sum(len(x) + TS_LEN for _, x in items)
                    items.sort(key=itemgetter(0))
                    ms = [q[0] for q in items]
                    sf = [q[1] for q in items]
                else:
                    ms = None
                if ms:
                    srv.write(''.join([(pm := p + m) + x.replace(NUL, pm) for m, x in zip(ms, sf)]))
                    if day == 0 and (s < boot_end or rnd() < p_con):
                        cp = hms + ','
                        con.write(''.join([(pm := cp + m) + x.replace(NUL, pm) for m, x in zip(ms, sf)
                                           if x[1] in 'IWEF']))
                # ---- app.log ----
                items = app.ev.pop(s, None)
                n = int(wm * app.kl * (0.6 + 0.8 * rnd()) + rnd()) if al else 0
                if n:
                    ms = sorted(choices(ms_all, k=n))
                    sf = choices(app.pool.entries, k=n)
                    if items:
                        app.ev_used += sum(len(x) + TS_LEN for _, x in items)
                        pairs = sorted(list(zip(ms, sf)) + items, key=itemgetter(0))
                        ms = [q[0] for q in pairs]
                        sf = [q[1] for q in pairs]
                elif items:
                    app.ev_used += sum(len(x) + TS_LEN for _, x in items)
                    items.sort(key=itemgetter(0))
                    ms = [q[0] for q in items]
                    sf = [q[1] for q in items]
                else:
                    continue
                pa = pre_sp + hms + '.'
                app.write(''.join([(pm := pa + m) + x.replace(NUL, pm) for m, x in zip(ms, sf)]))
            if day == 0 and mod == 1439:
                con.close()
        srv.close()
        app.close()
        con.close()
        elapsed = time.time() - t_start
        if not a.quiet:
            sys.stderr.write('\r' + ' ' * 70 + '\r')
        self.write_truth(elapsed)
        return elapsed

    def write_truth(self, elapsed):
        a = self.args
        files = []
        for sk, fmt in ((self.srv, '%d{yyyy-MM-dd HH:mm:ss,SSS} %-5p [%c] (%t) %s%e%n'),
                        (self.app, '%d{yyyy-MM-dd HH:mm:ss.SSS} [%t] %-5level %logger{36} - %msg%n'),
                        (self.con, '%d{HH:mm:ss,SSS} %-5p [%c] (%t) %s%e%n')):
            for name, b, n in sk.files:
                d = {'file': name, 'kind': sk.name, 'pattern': fmt, 'bytes_uncompressed': b, 'lines': n}
                if name.endswith('.gz'):
                    d['bytes_on_disk'] = os.path.getsize(os.path.join(a.out, name))
                m = re.match(r'server\.log\.(\d{4}-\d\d-\d\d)', name)
                if m:
                    d['date'] = m.group(1)
                elif name == 'server.log':
                    d['date'] = (self.start_date + dt.timedelta(days=self.D - 1)).isoformat()
                elif name == 'console.log':
                    d['date'] = self.start_date.isoformat()
                files.append(d)
        truth = {
            'generator': 'tools/genlogs.py',
            'seed': a.seed, 'days': self.D, 'requested_size_bytes': self.total,
            'actual_size_bytes': sum(f['bytes_uncompressed'] for f in files),
            'range_start': self.ts(0), 'range_end': self.ts(self.T - 0.001),
            'timezone': 'none (local time, no offset in logs)',
            'generation_seconds': round(elapsed, 2),
            'files': files,
            'incidents': self.incidents,
            'periodic_jobs': self.periodic,
            'background_templates': {
                k: [{'name': n, 'kind': kind, 'share_of_records': round(sh, 6)} for n, kind, sh in v]
                for k, v in self.tpl_shares.items()},
            'notes': [
                'Timestamps are local wall-clock time without zone; server.log.<date> holds exactly that date.',
                'Records belonging together (SQL + binds, SqlExceptionHelper + WFLYEJB0034) share a timestamp.',
                'Background noise templates are always present at low, steady rates; incidents are the anomalies.',
                'Incident counts are number of injected events (multi-line records count once).',
            ],
        }
        with open(os.path.join(a.out, 'ground_truth.json'), 'w') as fh:
            json.dump(truth, fh, indent=2)
        self.truth = truth


def main(argv=None):
    ap = argparse.ArgumentParser(description='Synthetic WildFly/log4j2 log generator with injected incidents.')
    ap.add_argument('--out', required=True, help='output directory')
    ap.add_argument('--size', type=parse_size, default=parse_size('500M'), help='total uncompressed size, e.g. 200M, 2G (default 500M)')
    ap.add_argument('--days', type=int, default=3, help='number of days (default 3)')
    ap.add_argument('--seed', type=int, default=42, help='random seed (default 42)')
    ap.add_argument('--start', help='first day YYYY-MM-DD (default: today minus --days)')
    ap.add_argument('--gzip-rotated', action='store_true', help='gzip rotated server.log.<date> files')
    ap.add_argument('--gzip-level', type=int, default=1, help='gzip level for rotated files (default 1, fast)')
    ap.add_argument('--quiet', action='store_true', help='no progress output')
    a = ap.parse_args(argv)
    if a.days < 1:
        ap.error('--days must be >= 1')
    if a.size < 1 << 20:
        ap.error('--size must be at least 1M')
    g = Gen(a)
    elapsed = g.run()
    t = g.truth
    total = t['actual_size_bytes']
    if not a.quiet:
        print('wrote %d files, %.1f MB in %.1f s (%.1f MB/s) to %s' % (
            len(t['files']) + 1, total / 1e6, elapsed, total / 1e6 / max(elapsed, 1e-9), a.out))
        for f in t['files']:
            print('  %-28s %10.1f MB %10d lines' % (f['file'], f['bytes_uncompressed'] / 1e6, f['lines']))
        print('incidents:')
        for d in t['incidents']:
            print('  #%-2d %-20s %s .. %s' % (d['id'], d['type'], d['start'], d['end']))


if __name__ == '__main__':
    main()
