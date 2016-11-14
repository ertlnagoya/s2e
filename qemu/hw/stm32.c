#include "stm32.h"

DeviceState *stm32_init_periph(DeviceState *dev, stm32_periph_t periph,
                                        target_phys_addr_t addr, qemu_irq irq)
{
    qdev_init_nofail(dev);
    sysbus_mmio_map(SYS_BUS_DEVICE(dev), 0, addr);
    if (irq) {
        sysbus_connect_irq(SYS_BUS_DEVICE(dev), 0, irq);
    }
    return dev;
}

void stm32_hw_warn(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    fprintf(stderr, "qemu stm32: hardware warning: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    cpu_dump_state(first_cpu, stderr, fprintf, 0);
    va_end(ap);
}

const char *stm32_periph_name_arr[] =
    {"RCC",
     "GPIOA",
     "GPIOB",
     "GPIOC",
     "GPIOD",
     "GPIOE",
     "GPIOF",
     "GPIOG",
     "AFIO",
     "UART1",
     "UART2",
     "UART3",
     "UART4",
     "UART5",
     "ADC1",
     "ADC2",
     "ADC3",
     "DAC",
     "TIM1",
     "TIM2",
     "TIM3",
     "TIM4",
     "TIM5",
     "TIM6",
     "TIM7",
     "TIM8",
     "BKP",
     "PWR",
     "I2C1",
     "I2C2",
     "I2S1",
     "I2S2",
     "IWDG"
     "WWDG",
     "CAN1",
     "CAN2",
     "CAN",
     "USB",
     "SPI1",
     "SPI2",
     "SPI3",
     "EXTI",
     "SDIO",
     "FSMC",
     "RTC"};

const char *stm32_periph_name(stm32_periph_t periph)
{
    assert(periph < STM32_PERIPH_COUNT);

    return stm32_periph_name_arr[periph];
}
