#!/usr/bin/env python3
"""Reproducible Nexus QLoRA entry point for the GPU workstation."""

from __future__ import annotations

import argparse
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--model", default="Qwen/Qwen3-4B")
    parser.add_argument("--output", type=Path, default=Path("artifacts/nexus-ai-lora"))
    parser.add_argument("--epochs", type=float, default=2.0)
    parser.add_argument("--max-length", type=int, default=2048)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if not args.dataset.is_file():
        raise SystemExit(f"Dataset not found: {args.dataset}")
    if args.dry_run:
        print(
            f"Ready: model={args.model} dataset={args.dataset} "
            f"output={args.output} epochs={args.epochs}"
        )
        return

    import torch
    from datasets import load_dataset
    from peft import LoraConfig
    from transformers import BitsAndBytesConfig
    from trl import SFTConfig, SFTTrainer

    if not torch.cuda.is_available():
        raise SystemExit("CUDA GPU required. Use --dry-run on this computer.")

    dataset = load_dataset("json", data_files=str(args.dataset), split="train")
    quantization = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.bfloat16,
        bnb_4bit_use_double_quant=True,
    )
    lora = LoraConfig(
        r=32,
        lora_alpha=64,
        lora_dropout=0.05,
        bias="none",
        task_type="CAUSAL_LM",
        target_modules="all-linear",
    )
    config = SFTConfig(
        output_dir=str(args.output),
        num_train_epochs=args.epochs,
        per_device_train_batch_size=1,
        gradient_accumulation_steps=8,
        learning_rate=1e-4,
        max_length=args.max_length,
        logging_steps=5,
        save_strategy="epoch",
        gradient_checkpointing=True,
        bf16=True,
        report_to="none",
        model_init_kwargs={
            "quantization_config": quantization,
            "device_map": "auto",
            "torch_dtype": torch.bfloat16,
        },
    )
    trainer = SFTTrainer(
        model=args.model,
        train_dataset=dataset,
        args=config,
        peft_config=lora,
    )
    trainer.train()
    trainer.save_model()


if __name__ == "__main__":
    main()
