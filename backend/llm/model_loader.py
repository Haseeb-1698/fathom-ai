"""
model_loader.py — Load Mixtral-8x7B in 4-bit with PEFT adapter support.

Ported from Plan A's benchmark_mixtral_hf.py with adapter switching support.
"""

from __future__ import annotations

from typing import Optional

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from peft import PeftModel

from config import BASE_MODEL_ID, LOAD_IN_4BIT, BNB_4BIT_COMPUTE_DTYPE, BNB_4BIT_QUANT_TYPE

# Module-level singletons
_model = None
_tokenizer = None
_current_adapter: Optional[str] = None


def get_bnb_config() -> BitsAndBytesConfig:
    compute_dtype = getattr(torch, BNB_4BIT_COMPUTE_DTYPE, torch.bfloat16)
    return BitsAndBytesConfig(
        load_in_4bit=LOAD_IN_4BIT,
        bnb_4bit_quant_type=BNB_4BIT_QUANT_TYPE,
        bnb_4bit_use_double_quant=True,
        bnb_4bit_compute_dtype=compute_dtype,
    )


def load_base_model(model_id: str | None = None, device_map: str = "auto"):
    """Load the base Mixtral model in 4-bit quantization."""
    global _model, _tokenizer

    if _model is not None:
        return _model, _tokenizer

    model_id = model_id or BASE_MODEL_ID

    print(f"[ModelLoader] Loading tokenizer: {model_id}")
    _tokenizer = AutoTokenizer.from_pretrained(model_id, use_fast=True)
    if _tokenizer.pad_token is None:
        _tokenizer.pad_token = _tokenizer.eos_token
    _tokenizer.padding_side = "left"  # left for generation

    print(f"[ModelLoader] Loading model in 4-bit: {model_id}")
    _model = AutoModelForCausalLM.from_pretrained(
        model_id,
        quantization_config=get_bnb_config(),
        device_map=device_map,
        torch_dtype=torch.bfloat16,
        low_cpu_mem_usage=True,
        attn_implementation="sdpa",
    )
    _model.eval()

    if torch.cuda.is_available():
        vram = torch.cuda.get_device_properties(0).total_mem / 1e9
        print(f"[ModelLoader] Loaded on {torch.cuda.get_device_name(0)} ({vram:.1f} GB)")

    return _model, _tokenizer


def load_adapter(adapter_path: str) -> None:
    """Load or switch to a PEFT LoRA adapter."""
    global _model, _current_adapter

    if _model is None:
        raise RuntimeError("Base model not loaded. Call load_base_model() first.")

    if _current_adapter == adapter_path:
        return  # already loaded

    if isinstance(_model, PeftModel):
        # Model already has adapters — try to load new one
        try:
            adapter_name = adapter_path.replace("/", "_").replace("\\", "_")
            _model.load_adapter(adapter_path, adapter_name=adapter_name)
            _model.set_adapter(adapter_name)
            _current_adapter = adapter_path
            print(f"[ModelLoader] Switched to adapter: {adapter_path}")
            return
        except Exception as e:
            print(f"[ModelLoader] Warning: adapter switch failed ({e}), attempting fresh load")

    # First adapter load — wrap base model with PeftModel
    _model = PeftModel.from_pretrained(_model, adapter_path)
    _model.eval()
    _current_adapter = adapter_path
    print(f"[ModelLoader] Loaded adapter: {adapter_path}")


def get_model_and_tokenizer():
    """Get the current model and tokenizer (loading if needed)."""
    if _model is None:
        load_base_model()
    return _model, _tokenizer


def get_current_adapter() -> Optional[str]:
    return _current_adapter
