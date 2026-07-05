import type { ButtonHTMLAttributes } from "react";
import { forwardRef } from "react";
import { Slot } from "@radix-ui/react-slot";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const buttonVariants = cva(
  "inline-flex items-center justify-center rounded-lg text-sm font-medium \
   transition-colors focus-visible:outline-none focus-visible:ring-2 \
   focus-visible:ring-brand-500 disabled:pointer-events-none disabled:opacity-50 \
   cursor-pointer",
  {
    variants: {
      variant: {
        default: "bg-brand-700 text-white hover:bg-brand-600",
        danger: "bg-danger text-white hover:bg-red-600",
        success: "bg-success text-white hover:bg-green-600",
        warning: "bg-warning text-black hover:bg-amber-500",
        outline:
          "border border-surface-800 bg-transparent hover:bg-surface-800",
        ghost: "hover:bg-surface-800 text-surface-100",
      },
      size: {
        sm: "h-8 px-3 text-xs",
        md: "h-10 px-4 text-sm",
        lg: "h-12 px-6 text-base",
        icon: "h-10 w-10",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "md",
    },
  },
);

export interface ButtonProps
  extends ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean;
}

const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, asChild = false, ...props }, ref) => {
    const Comp = asChild ? Slot : "button";
    return (
      <Comp
        className={cn(buttonVariants({ variant, size, className }))}
        ref={ref}
        {...props}
      />
    );
  },
);
Button.displayName = "Button";

export { Button, buttonVariants };
