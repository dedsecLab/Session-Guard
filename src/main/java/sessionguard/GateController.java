package sessionguard;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Thread-safe gate that blocks scanner/extension threads when session has expired.
 * Uses CountDownLatch for efficient thread parking (no CPU spin).
 *
 * Flow:
 *   1. pause()          → creates a new latch, sets paused=true. All future awaitIfPaused() callers block.
 *   2. awaitIfPaused()  → called on every outgoing request. Blocks if paused, returns instantly if not.
 *   3. resume(grace)    → counts down the latch, releasing all blocked threads.
 *                         Sets a grace counter so that stale in-flight responses don't re-trigger pause.
 *
 * Grace period:
 *   After resume, the first N responses matching a trigger code are ignored (not re-paused).
 *   This drains the stale pipeline from the resource pool without false re-triggers.
 */
public class GateController {

    private volatile boolean paused = false;
    private volatile CountDownLatch latch = new CountDownLatch(0);
    private final Object lock = new Object();
    private final AtomicInteger blockedCount = new AtomicInteger(0);
    private final AtomicInteger graceRemaining = new AtomicInteger(0);

    /**
     * Activates the gate. All subsequent calls to awaitIfPaused() will block
     * until resume() is called.
     * @return true if the gate was successfully paused, false if it was already paused
     */
    public boolean pause() {
        synchronized (lock) {
            if (!paused) {
                latch = new CountDownLatch(1);
                paused = true;
                blockedCount.set(0);
                return true;
            }
            return false;
        }
    }

    /**
     * Opens the gate with a grace period. All threads blocked in awaitIfPaused()
     * are released immediately. The next {@code graceCount} trigger-code responses
     * will be silently ignored to drain stale in-flight requests.
     *
     * @param graceCount number of trigger responses to ignore after resume (0 = no grace)
     */
    public void resume(int graceCount) {
        synchronized (lock) {
            if (paused) {
                graceRemaining.set(Math.max(0, graceCount));
                paused = false;
                latch.countDown();
            }
        }
    }

    /**
     * Try to consume one grace token. Called by the handler when a trigger
     * response is received and the gate is NOT paused.
     *
     * @return true if a grace token was consumed (caller should ignore the trigger),
     *         false if no grace remaining (caller should trigger a pause)
     */
    public boolean consumeGrace() {
        int remaining = graceRemaining.get();
        while (remaining > 0) {
            if (graceRemaining.compareAndSet(remaining, remaining - 1)) {
                return true; // consumed — ignore this trigger
            }
            remaining = graceRemaining.get(); // retry CAS
        }
        return false; // no grace left — this is a real session expiry
    }

    /**
     * Blocks the calling thread if the gate is closed (session expired).
     * Returns immediately if the gate is open (zero overhead in normal operation).
     *
     * @throws InterruptedException if the thread is interrupted while waiting
     */
    public void awaitIfPaused() throws InterruptedException {
        // Capture latch reference under lock to avoid race between pause/resume cycles
        CountDownLatch currentLatch;
        synchronized (lock) {
            if (!paused) {
                return;
            }
            currentLatch = latch;
        }
        // Increment blocked count (visible to UI)
        blockedCount.incrementAndGet();
        // Block outside the lock — lets resume() be called while we wait
        currentLatch.await();
    }

    /**
     * @return true if the gate is currently closed (session expired, scanner paused)
     */
    public boolean isPaused() {
        return paused;
    }

    /**
     * @return number of requests that have been blocked since the last pause
     */
    public int getBlockedCount() {
        return blockedCount.get();
    }

    /**
     * @return number of grace tokens remaining
     */
    public int getGraceRemaining() {
        return graceRemaining.get();
    }
}
