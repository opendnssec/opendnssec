class Time
  class << self
    alias_method :original_now, :now
    def now
      if (!@start)
        @start = original_now.to_i
      end
      return Runner.timeshift + (original_now.to_i - @start)
    end
  end
end
