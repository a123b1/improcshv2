
static int nocompress;
static int noresume;
static int nohibernate; 
static int resume_wait;
static unsigned int resume_delay;
static char resume_file[256] = CONFIG_PM_STD_PARTITION;

enum {
	HIBERNATION_INVALID,
	HIBERNATION_PLATFORM,
	HIBERNATION_SHUTDOWN,
	HIBERNATION_REBOOT,
#ifdef CONFIG_SUSPEND
	HIBERNATION_SUSPEND,
#endif
	HIBERNATION_TEST_RESUME,
	/* keep last */
	__HIBERNATION_AFTER_LAST
};
#define HIBERNATION_MAX (__HIBERNATION_AFTER_LAST-1)
#define HIBERNATION_FIRST (HIBERNATION_INVALID + 1)

static int hibernation_mode = HIBERNATION_SHUTDOWN;

bool freezer_test_done;

static const struct platform_hibernation_ops *hibernation_ops;

static atomic_t hibernate_atomic = ATOMIC_INIT(1);

bool hibernate_acquire(void)
{
	return atomic_add_unless(&hibernate_atomic, -1, 0);
}
/**
 * hibernation_set_ops - Set the global hibernate operations.
 * @ops: Hibernation operations to use in subsequent hibernation transitions.
 */
void hibernation_set_ops(const struct platform_hibernation_ops *ops)
{
	unsigned int sleep_flags;

	if (ops && !(ops->begin && ops->end &&  ops->pre_snapshot
	    && ops->prepare && ops->finish && ops->enter && ops->pre_restore
	    && ops->restore_cleanup && ops->leave)) {
		WARN_ON(1);
		return;
	}

	sleep_flags = lock_system_sleep();

	hibernation_ops = ops;
	if (ops)
		hibernation_mode = HIBERNATION_PLATFORM;
	else if (hibernation_mode == HIBERNATION_PLATFORM)
		hibernation_mode = HIBERNATION_SHUTDOWN;

	unlock_system_sleep(sleep_flags);
}
EXPORT_SYMBOL_GPL(hibernation_set_ops);

static bool entering_platform_hibernation;

bool system_entering_hibernation(void)
{
	return entering_platform_hibernation;
}
EXPORT_SYMBOL(system_entering_hibernation);

#ifdef CONFIG_PM_DEBUG
static void hibernation_debug_sleep(void)
{
	pr_info("debug: Waiting for 5 seconds.\n");
	mdelay(5000);
}

static int hibernation_test(int level)
{
	if (pm_test_level == level) {
		hibernation_debug_sleep();
		return 1;
	}
	return 0;
}
#else /* !CONFIG_PM_DEBUG */
static int hibernation_test(int level) { return 0; }
#endif /* !CONFIG_PM_DEBUG */

/**
 * platform_begin - Call platform to start hibernation.
 * @platform_mode: Whether or not to use the platform driver.
 */
static int platform_begin(int platform_mode)
{
	return (platform_mode && hibernation_ops) ?
		hibernation_ops->begin(PMSG_FREEZE) : 0;
}

/**
 * platform_end - Call platform to finish transition to the working state.
 * @platform_mode: Whether or not to use the platform driver.
 */
static void platform_end(int platform_mode)
{
	if (platform_mode && hibernation_ops)
		hibernation_ops->end();
}

/**
 * platform_pre_snapshot - Call platform to prepare the machine for hibernation.
 * @platform_mode: Whether or not to use the platform driver.
 *
 * Use the platform driver to prepare the system for creating a hibernate image,
 * if so configured, and return an error code if that fails.
 */

static int platform_pre_snapshot(int platform_mode)
{
	return (platform_mode && hibernation_ops) ?
		hibernation_ops->pre_snapshot() : 0;
}

/**
 * platform_leave - Call platform to prepare a transition to the working state.
 * @platform_mode: Whether or not to use the platform driver.
 *
 * Use the platform driver prepare to prepare the machine for switching to the
 * normal mode of operation.
 *
 * This routine is called on one CPU with interrupts disabled.
 */
static void platform_leave(int platform_mode)
{
	if (platform_mode && hibernation_ops)
		hibernation_ops->leave();
}

/**
 * platform_finish - Call platform to switch the system to the working state.
 * @platform_mode: Whether or not to use the platform driver.
 *
 * Use the platform driver to switch the machine to the normal mode of
 * operation.
 *
 * This routine must be called after platform_prepare().
 */
static void platform_finish(int platform_mode)
{
	if (platform_mode && hibernation_ops)
		hibernation_ops->finish();
}

/**
 * platform_pre_restore - Prepare for hibernate image restoration.
 * @platform_mode: Whether or not to use the platform driver.
 *
 * Use the platform driver to prepare the system for resume from a hibernation
 * image.
 *
 * If the restore fails after this function has been called,
 * platform_restore_cleanup() must be called.
 */
static int platform_pre_restore(int platform_mode)
{
	return (platform_mode && hibernation_ops) ?
		hibernation_ops->pre_restore() : 0;
}

/**
 * platform_restore_cleanup - Switch to the working state after failing restore.
 * @platform_mode: Whether or not to use the platform driver.
 *
 * Use the platform driver to switch the system to the normal mode of operation
 * after a failing restore.
 *
 * If platform_pre_restore() has been called before the failing restore, this
 * function must be called too, regardless of the result of
 * platform_pre_restore().
 */
static void platform_restore_cleanup(int platform_mode)
{
	if (platform_mode && hibernation_ops)
		hibernation_ops->restore_cleanup();
}

/**
 * platform_recover - Recover from a failure to suspend devices.
 * @platform_mode: Whether or not to use the platform driver.
 */
static void platform_recover(int platform_mode)
{
	if (platform_mode && hibernation_ops && hibernation_ops->recover)
		hibernation_ops->recover();
}

void hibernate_release(void)
{
	atomic_inc(&hibernate_atomic);
}

bool hibernation_available(void)
{
	return nohibernate == 0 &&
		!security_locked_down(LOCKDOWN_HIBERNATION) &&
		!secretmem_active() && !cxl_mem_active();
}


/**
 * swsusp_show_speed - Print time elapsed between two events during hibernation.
 * @start: Starting event.
 * @stop: Final event.
 * @nr_pages: Number of memory pages processed between @start and @stop.
 * @msg: Additional diagnostic message to print.
 */
void swsusp_show_speed(ktime_t start, ktime_t stop,
		      unsigned nr_pages, char *msg)
{
	ktime_t diff;
	u64 elapsed_centisecs64;
	unsigned int centisecs;
	unsigned int k;
	unsigned int kps;

	diff = ktime_sub(stop, start);
	elapsed_centisecs64 = ktime_divns(diff, 10*NSEC_PER_MSEC);
	centisecs = elapsed_centisecs64;
	if (centisecs == 0)
		centisecs = 1;	/* avoid div-by-zero */
	k = nr_pages * (PAGE_SIZE / 1024);
	kps = (k * 100) / centisecs;
	pr_info("%s %u kbytes in %u.%02u seconds (%u.%02u MB/s)\n",
		msg, k, centisecs / 100, centisecs % 100, kps / 1000,
		(kps % 1000) / 10);
}

__weak int arch_resume_nosmt(void)
{
	return 0;
}

/**
 * create_image - Create a hibernation image.
 * @platform_mode: Whether or not to use the platform driver.
 *
 * Execute device drivers' "late" and "noirq" freeze callbacks, create a
 * hibernation image and run the drivers' "noirq" and "early" thaw callbacks.
 *
 * Control reappears in this routine after the subsequent restore.
 */
static int create_image(int platform_mode)
{
	int error;

	error = dpm_suspend_end(PMSG_FREEZE);
	if (error) {
		pr_err("Some devices failed to power down, aborting\n");
		return error;
	}

	error = platform_pre_snapshot(platform_mode);
	if (error || hibernation_test(TEST_PLATFORM))
		goto Platform_finish;

	error = pm_sleep_disable_secondary_cpus();
	if (error || hibernation_test(TEST_CPUS))
		goto Enable_cpus;

	local_irq_disable();

	system_state = SYSTEM_SUSPEND;

	error = syscore_suspend();
	if (error) {
		pr_err("Some system devices failed to power down, aborting\n");
		goto Enable_irqs;
	}

	if (hibernation_test(TEST_CORE) || pm_wakeup_pending())
		goto Power_up;

	in_suspend = 1;
	save_processor_state();
	trace_suspend_resume(TPS("machine_suspend"), PM_EVENT_HIBERNATE, true);
	error = swsusp_arch_suspend();
	/* Restore control flow magically appears here */
	restore_processor_state();
	trace_suspend_resume(TPS("machine_suspend"), PM_EVENT_HIBERNATE, false);
	if (error)
		pr_err("Error %d creating image\n", error);

	if (!in_suspend) {
		events_check_enabled = false;
		clear_or_poison_free_pages();
	}

	platform_leave(platform_mode);

 Power_up:
	syscore_resume();

 Enable_irqs:
	system_state = SYSTEM_RUNNING;
	local_irq_enable();

 Enable_cpus:
	pm_sleep_enable_secondary_cpus();

	/* Allow architectures to do nosmt-specific post-resume dances */
	if (!in_suspend)
		error = arch_resume_nosmt();

 Platform_finish:
	platform_finish(platform_mode);

	dpm_resume_start(in_suspend ?
		(error ? PMSG_RECOVER : PMSG_THAW) : PMSG_RESTORE);

	return error;
}

/**
 * hibernation_snapshot - Quiesce devices and create a hibernation image.
 * @platform_mode: If set, use platform driver to prepare for the transition.
 *
 * This routine must be called with system_transition_mutex held.
 */
int hibernation_snapshot(int platform_mode)
{
	pm_message_t msg;
	int error;

	pm_suspend_clear_flags();
	error = platform_begin(platform_mode);
	if (error)
		goto Close;

	/* Preallocate image memory before shutting down devices. */
	error = hibernate_preallocate_memory();
	if (error)
		goto Close;
